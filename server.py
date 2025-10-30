import os
import json
import uuid
from datetime import datetime, timedelta, UTC
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import jwt

# --- Configuración Inicial de Flask ---
app = Flask(__name__)
# Permitir CORS desde el puerto 5000 (o el que uses)
CORS(app, resources={r"/*": {"origins": "*"}}) 

# Configuración de base de datos SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///gastos_db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'mi_clave_secreta_super_segura_123' # Cambia esto en producción
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24) 
app.config['UPLOAD_FOLDER'] = 'uploads'

db = SQLAlchemy(app)

# Crear el directorio de subidas si no existe
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# --- Modelos de Base de Datos (SQLAlchemy) ---

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cedula = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    rol = db.Column(db.String(20), nullable=False, default='titular_view') 
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
class Titular(db.Model):
    cedula = db.Column(db.String(20), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    nombre = db.Column(db.String(100), nullable=False)
    apellido = db.Column(db.String(100), nullable=False)
    vicerrectorado = db.Column(db.String(50))
    condicion = db.Column(db.String(50))
    
    familiares = db.relationship('Familiar', backref='titular', lazy=True, cascade="all, delete-orphan")
    gastos = db.relationship('Gasto', backref='titular', lazy=True, cascade="all, delete-orphan")
    
    def to_dict(self):
        return {
            'cedula': self.cedula,
            'nombre': self.nombre,
            'apellido': self.apellido,
            'vicerrectorado': self.vicerrectorado,
            'condicion': self.condicion
        }

class Familiar(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cedula_titular = db.Column(db.String(20), db.ForeignKey('titular.cedula'), nullable=False)
    cedula_familiar = db.Column(db.String(20), nullable=False)
    nombre_familiar = db.Column(db.String(100), nullable=False)
    apellido_familiar = db.Column(db.String(100), nullable=False)
    parentesco = db.Column(db.String(50))
    fecha_nacimiento = db.Column(db.String(10)) 
    carga_familiar_pdf = db.Column(db.String(255)) 

    def to_dict(self):
        return {
            'id': self.id,
            'cedula_titular': self.cedula_titular,
            'cedula_familiar': self.cedula_familiar,
            'nombre_familiar': self.nombre_familiar,
            'apellido_familiar': self.apellido_familiar,
            'parentesco': self.parentesco,
            'fecha_nacimiento': self.fecha_nacimiento,
            'carga_familiar_pdf': self.carga_familiar_pdf 
        }
        
class Gasto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    titular_cedula = db.Column(db.String(20), db.ForeignKey('titular.cedula'), nullable=False)
    beneficiario_cedula = db.Column(db.String(20), nullable=False)
    fecha_gasto = db.Column(db.String(10), nullable=False)
    numero_factura = db.Column(db.String(50))
    farmacia_clinica = db.Column(db.String(100))
    diagnostico = db.Column(db.String(100))
    tipo_gasto = db.Column(db.String(50))
    medicamentos_permanentes = db.Column(db.String(255), default='')
    monto = db.Column(db.Float, nullable=False)
    estado = db.Column(db.String(50), default='Recibido')
    mensaje_admin = db.Column(db.String(255), default='')
    fotos_json = db.Column(db.Text, default='[]') 

    def to_dict(self):
        return {
            'id': self.id,
            'titular_cedula': self.titular_cedula,
            'beneficiario_cedula': self.beneficiario_cedula,
            'fecha_gasto': self.fecha_gasto,
            'numero_factura': self.numero_factura,
            'farmacia_clinica': self.farmacia_clinica,
            'diagnostico': self.diagnostico,
            'tipo_gasto': self.tipo_gasto,
            'medicamentos_permanentes': self.medicamentos_permanentes,
            'monto': self.monto,
            'estado': self.estado,
            'mensaje_admin': self.mensaje_admin,
            'fotos': json.loads(self.fotos_json)
        }
    
# Inicializar la base de datos dentro del contexto de la aplicación
with app.app_context():
    db.create_all()

# --- Decoradores (sin cambios) ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        if not token:
            return jsonify({'message': 'Token de autenticación faltante.'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(cedula=data['user_cedula']).first()
            if not current_user:
                 return jsonify({'message': 'Usuario no encontrado o token inválido.'}), 401
            request.current_user = current_user 
            request.user_role = data['user_rol']
        except Exception as e:
            return jsonify({'message': f'Token inválido o expirado. {e}'}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    @token_required
    def decorated_function(*args, **kwargs):
        if request.user_role != 'admin':
            return jsonify({'message': 'Acceso denegado. Se requiere rol de Administrador.'}), 403
        return f(*args, **kwargs)
    return decorated_function

# --- Rutas de Autenticación (sin cambios mayores) ---

@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    cedula = data.get('cedula')
    password = data.get('password')
    if not cedula or not password:
        return jsonify({'message': 'Cédula y contraseña son requeridas.'}), 400
    if len(password) < 6:
        return jsonify({'message': 'La contraseña debe tener al menos 6 caracteres.'}), 400
    user = User.query.filter_by(cedula=cedula).first()
    if user:
        return jsonify({'message': 'Ya existe un usuario con esta cédula.'}), 409
    if User.query.count() == 0:
        new_user = User(cedula=cedula, rol='admin')
    else:
        new_user = User(cedula=cedula, rol='titular_view') 
    new_user.set_password(password)
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': f'Usuario {cedula} registrado con éxito. Rol: {new_user.rol}.'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error al registrar usuario: {e}'}), 500

@app.route('/register-titular', methods=['POST'])
@admin_required
def register_titular_view():
    data = request.get_json()
    cedula = data.get('cedula')
    password = data.get('password')
    if not cedula or not password:
        return jsonify({'message': 'Cédula y contraseña son requeridas.'}), 400
    user = User.query.filter_by(cedula=cedula).first()
    if not user:
        new_user = User(cedula=cedula, rol='titular_view')
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': f'Usuario Titular de Acceso {cedula} registrado con éxito. Puede continuar con la información del titular.'}), 201
    return jsonify({'message': f'El usuario de acceso para {cedula} ya existe. Puede continuar con la información del titular.'}), 200

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    cedula = data.get('cedula')
    password = data.get('password')
    user = User.query.filter_by(cedula=cedula).first()
    if not user or not user.check_password(password):
        return jsonify({'message': 'Credenciales inválidas.'}), 401
    token = jwt.encode({
        'user_cedula': user.cedula,
        'user_rol': user.rol,
        'exp': datetime.now(UTC) + app.config['PERMANENT_SESSION_LIFETIME']
    }, app.config['SECRET_KEY'], algorithm="HS256")
    return jsonify({'message': 'Inicio de sesión exitoso.', 'token': token, 'rol': user.rol}), 200

@app.route('/titular/password', methods=['PUT'])
@token_required
def change_password():
    data = request.get_json()
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    user = request.current_user
    if not old_password or not new_password:
        return jsonify({'message': 'Contraseña actual y nueva son requeridas.'}), 400
    if len(new_password) < 6:
        return jsonify({'message': 'La nueva contraseña debe tener al menos 6 caracteres.'}), 400
    if not user.check_password(old_password):
        return jsonify({'message': 'Contraseña actual incorrecta.'}), 401
    try:
        user.set_password(new_password)
        db.session.commit()
        return jsonify({'message': 'Contraseña actualizada con éxito.'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error al actualizar la contraseña: {e}'}), 500

# --- Rutas de Titulares (sin cambios) ---

@app.route('/titulares', methods=['POST'])
@admin_required
def create_titular():
    data = request.get_json()
    cedula = data.get('cedula')
    if not cedula:
        return jsonify({'message': 'La cédula es requerida.'}), 400
    if Titular.query.filter_by(cedula=cedula).first():
        return jsonify({'message': 'El titular ya está registrado. Actualizado.'}), 200
    user = User.query.filter_by(cedula=cedula).first()
    if not user:
        return jsonify({'message': 'El usuario de acceso Titular_View debe registrarse primero.'}), 400
    try:
        new_titular = Titular(
            cedula=cedula,
            user_id=user.id,
            nombre=data.get('nombre'),
            apellido=data.get('apellido'),
            vicerrectorado=data.get('vicerrectorado'),
            condicion=data.get('condicion')
        )
        db.session.add(new_titular)
        db.session.commit()
        return jsonify({'message': f'Titular {new_titular.nombre} {new_titular.apellido} registrado con éxito.'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error al crear titular: {e}'}), 500

@app.route('/titulares/<query>', methods=['GET'])
@token_required
def get_titular(query):
    if request.user_role == 'titular_view':
        if query != request.current_user.cedula:
            return jsonify({'message': 'Acceso denegado. Solo puede ver su propia información.'}), 403
        cedula_to_find = query
    elif query.isdigit():
        cedula_to_find = query
    else:
        titular = Titular.query.filter(
            (Titular.nombre.ilike(f'%{query}%')) | 
            (Titular.apellido.ilike(f'%{query}%'))
        ).first()
        if titular:
            return jsonify(titular.to_dict()), 200
        else:
            return jsonify({'message': 'Titular no encontrado por nombre o apellido.'}), 404
    titular = Titular.query.filter_by(cedula=cedula_to_find).first()
    if titular:
        return jsonify(titular.to_dict()), 200
    return jsonify({'message': 'Titular no encontrado por cédula.'}), 404

# --- Rutas de Familiares (CORREGIDAS y AÑADIDA LÓGICA DE ELIMINACIÓN) ---

@app.route('/familiares/upload', methods=['POST'])
@admin_required
def upload_familiar():
    """Crea un familiar y maneja la subida de la Carga Familiar PDF usando FormData."""
    cedula_titular = request.form.get('cedulaTitular')
    if not cedula_titular:
        return jsonify({'message': 'La cédula del titular es requerida.'}), 400
    titular = Titular.query.filter_by(cedula=cedula_titular).first()
    if not titular:
        return jsonify({'message': 'Titular no encontrado.'}), 404

    pdf_filename = ''
    if 'carga_familiar_pdf' in request.files:
        pdf_file = request.files['carga_familiar_pdf']
        if pdf_file and pdf_file.filename != '':
            if allowed_file(pdf_file.filename) and pdf_file.filename.lower().endswith('.pdf'):
                # 1. Guarda el PDF y almacena solo el nombre.
                pdf_filename = str(uuid.uuid4()) + os.path.splitext(pdf_file.filename)[1]
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], pdf_filename)
                pdf_file.save(filepath)
            else:
                return jsonify({'message': 'El archivo de carga familiar debe ser un PDF válido.'}), 400

    try:
        new_familiar = Familiar(
            cedula_titular=cedula_titular,
            cedula_familiar=request.form.get('cedulaFamiliar'),
            nombre_familiar=request.form.get('nombreFamiliar'),
            apellido_familiar=request.form.get('apellidoFamiliar'),
            parentesco=request.form.get('parentesco'),
            fecha_nacimiento=request.form.get('fechaNacimiento'),
            carga_familiar_pdf=pdf_filename 
        )
        db.session.add(new_familiar)
        db.session.commit()
        return jsonify({'message': f'Familiar {new_familiar.nombre_familiar} registrado con éxito y archivo guardado.'}), 201
    except Exception as e:
        db.session.rollback()
        # Si la DB falla, intenta eliminar el archivo subido
        if pdf_filename and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], pdf_filename)):
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], pdf_filename))
        return jsonify({'message': f'Error al crear familiar: {e}'}), 500


@app.route('/familiares/<cedulaTitular>', methods=['GET'])
@token_required
def get_familiares(cedulaTitular):
    if request.user_role == 'titular_view':
        if cedulaTitular != request.current_user.cedula:
            return jsonify({'message': 'Acceso denegado. Solo puede ver sus propios familiares.'}), 403
    familiares = Familiar.query.filter_by(cedula_titular=cedulaTitular).all()
    return jsonify([f.to_dict() for f in familiares]), 200

@app.route('/familiares/<int:familiarId>', methods=['DELETE'])
@admin_required
def delete_familiar(familiarId):
    familiar = Familiar.query.get(familiarId)
    if not familiar:
        return jsonify({'message': 'Familiar no encontrado.'}), 404
    
    pdf_to_delete = familiar.carga_familiar_pdf

    try:
        db.session.delete(familiar)
        db.session.commit()
        
        # Eliminar el archivo del disco (Esta lógica ya estaba, pero es fundamental)
        if pdf_to_delete:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], pdf_to_delete)
            if os.path.exists(filepath):
                os.remove(filepath)
        
        return jsonify({'message': f'Familiar eliminado con éxito.'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error al eliminar familiar: {e}'}), 500

# --- Rutas de Archivos Estáticos (SOLUCIÓN al 404 del PDF) ---

def allowed_file(filename):
    """Verifica si la extensión del archivo está permitida."""
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/gastos/upload', methods=['POST'])
@admin_required
def upload_gasto():
    metadata_json = request.form.get('metadata')
    if not metadata_json:
        return jsonify({'message': 'Metadata (datos del gasto) faltante.'}), 400
    
    try:
        data = json.loads(metadata_json)
    except json.JSONDecodeError:
        return jsonify({'message': 'Formato JSON de metadata inválido.'}), 400

    titular_id = data.get('titularId')
    
    if not titular_id:
        return jsonify({'message': 'Cédula del titular faltante.'}), 400
        
    titular = Titular.query.filter_by(cedula=titular_id).first()
    if not titular:
        return jsonify({'message': 'Titular no encontrado.'}), 404

    fotos_filenames = []
    if 'files' in request.files:
        files = request.files.getlist('files')
        for file in files:
            if file.filename == '':
                continue
            if file and allowed_file(file.filename):
                filename = str(uuid.uuid4()) + os.path.splitext(file.filename)[1]
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                fotos_filenames.append(filename) 
            else:
                return jsonify({'message': 'Tipo de archivo no permitido. Solo imágenes y PDF.'}), 400

    try:
        new_gasto = Gasto(
            titular_cedula=titular_id,
            beneficiario_cedula=data.get('beneficiarioId'),
            fecha_gasto=data.get('fecha'),
            numero_factura=data.get('factura'),
            farmacia_clinica=data.get('farmaciaClinica'),
            diagnostico=data.get('diagnostico'),
            tipo_gasto=data.get('tipoGasto'),
            medicamentos_permanentes=data.get('medicamentos'),
            monto=data.get('monto'),
            fotos_json=json.dumps(fotos_filenames) 
        )
        db.session.add(new_gasto)
        db.session.commit()
        
        return jsonify({'message': f'Gasto de {titular.nombre} registrado con éxito. Archivos guardados: {len(fotos_filenames)}.'}), 201
    except Exception as e:
        db.session.rollback()
        for filename in fotos_filenames:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.exists(filepath):
                os.remove(filepath)
        return jsonify({'message': f'Error al guardar el gasto en la base de datos: {e}'}), 500

@app.route('/uploads/<filename>', methods=['GET'])
# Se elimina @token_required para que los navegadores puedan acceder directamente a los archivos.
def uploaded_file(filename):
    """Sirve archivos estáticos de la carpeta de subidas SIN autenticación."""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# --- Rutas de Reportes y Mantenimiento (sin cambios) ---

@app.route('/gastos/<cedulaTitular>', methods=['GET'])
@token_required
def get_gastos_by_titular(cedulaTitular):
    if request.user_role == 'titular_view':
        if cedulaTitular != request.current_user.cedula:
            return jsonify({'message': 'Acceso denegado. Solo puede ver sus propios gastos.'}), 403

    gastos = Gasto.query.filter_by(titular_cedula=cedulaTitular).order_by(Gasto.fecha_gasto.desc()).all()
    titular = Titular.query.filter_by(cedula=cedulaTitular).first()
    gastos_list = []
    if titular:
        for gasto in gastos:
            gasto_dict = gasto.to_dict()
            gasto_dict['titular_nombre'] = titular.nombre
            gasto_dict['titular_apellido'] = titular.apellido
            gastos_list.append(gasto_dict)
    return jsonify(gastos_list), 200

@app.route('/gastos/estado/<int:gastoId>', methods=['PUT'])
@admin_required
def update_gasto_status(gastoId):
    data = request.get_json()
    new_status = data.get('estado')
    gasto = Gasto.query.get(gastoId)
    if not gasto:
        return jsonify({'message': 'Gasto no encontrado.'}), 404
    gasto.estado = new_status
    try:
        db.session.commit()
        return jsonify({'message': f'Estado del gasto {gastoId} actualizado a {new_status}.'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error al actualizar el estado: {e}'}), 500

@app.route('/gastos/mensaje/<int:gastoId>', methods=['PUT'])
@admin_required
def update_admin_message(gastoId):
    data = request.get_json()
    new_message = data.get('mensaje')
    gasto = Gasto.query.get(gastoId)
    if not gasto:
        return jsonify({'message': 'Gasto no encontrado.'}), 404
    gasto.mensaje_admin = new_message
    try:
        db.session.commit()
        return jsonify({'message': f'Mensaje de administrador del gasto {gastoId} actualizado.'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error al actualizar el mensaje: {e}'}), 500

@app.route('/reportes/gastos', methods=['GET'])
@admin_required
def get_reporte_gastos():
    tipo_gasto = request.args.get('tipo_gasto')
    vicerrectorado = request.args.get('vicerrectorado')
    condicion = request.args.get('condicion')
    query = Gasto.query.join(Titular, Gasto.titular_cedula == Titular.cedula)
    if tipo_gasto and tipo_gasto != 'todos':
        query = query.filter(Gasto.tipo_gasto == tipo_gasto)
    if vicerrectorado and vicerrectorado != 'todos':
        query = query.filter(Titular.vicerrectorado == vicerrectorado)
    if condicion and condicion != 'todos':
        query = query.filter(Titular.condicion == condicion)
    gastos = query.all()
    reporte = []
    for gasto in gastos:
        titular = Titular.query.filter_by(cedula=gasto.titular_cedula).first() 
        if titular:
            gasto_dict = gasto.to_dict()
            gasto_dict['titular_nombre'] = titular.nombre
            gasto_dict['titular_apellido'] = titular.apellido
            gasto_dict['vicerrectorado'] = titular.vicerrectorado
            gasto_dict['condicion'] = titular.condicion
            reporte.append(gasto_dict)
    return jsonify(reporte), 200

@app.route('/reportar_error', methods=['POST'])
@token_required
def report_error():
    data = request.get_json()
    details = data.get('details')
    user_cedula = request.current_user.cedula
    user_role = request.user_role
    if not details:
        return jsonify({'message': 'Los detalles del reporte son requeridos.'}), 400
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("\n--- ¡NUEVO REPORTE DE ERROR! ---")
    print(f"Fecha/Hora: {timestamp}")
    print(f"Usuario: {user_cedula} (Rol: {user_role})")
    print(f"Detalles: {details}")
    print("---------------------------------\n")
    return jsonify({'message': 'Reporte de problema enviado al administrador con éxito.'}), 200

@app.route('/mantenimiento/reset_data', methods=['DELETE'])
@admin_required
def reset_data():
    try:
        num_gastos = Gasto.query.delete()
        
        familiares = Familiar.query.all()
        for f in familiares:
            if f.carga_familiar_pdf:
                 filepath = os.path.join(app.config['UPLOAD_FOLDER'], f.carga_familiar_pdf)
                 if os.path.exists(filepath):
                     os.remove(filepath)
        
        num_familiares = Familiar.query.delete()
        titulares = Titular.query.all()
        user_ids_to_delete = [t.user_id for t in titulares if t.user_id]
        num_titulares = Titular.query.delete()
        
        num_users_deleted = 0
        for user_id in user_ids_to_delete:
            user = User.query.get(user_id)
            if user and user.rol == 'titular_view':
                db.session.delete(user)
                num_users_deleted += 1

        db.session.commit()
        
        deleted_files = 0
        for filename in os.listdir(app.config['UPLOAD_FOLDER']):
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.isfile(filepath):
                os.remove(filepath)
                deleted_files += 1

        message = (f"Reset completado. Eliminados: {num_titulares} Titulares, {num_familiares} Familiares, "
                   f"{num_gastos} Gastos, {num_users_deleted} Usuarios Titulares, {deleted_files} Archivos.")
        return jsonify({'message': message}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error al resetear los datos: {e}'}), 500
# --- RUTA ADICIONAL PARA ESTADÍSTICAS GLOBALES ---

@app.route('/reportes/estadisticas', methods=['GET'])
@admin_required
def get_global_statistics():
    """Calcula y devuelve las estadísticas globales de gastos, incluyendo agrupaciones para gráficos."""
    
    # Obtener filtros de año y mes desde la solicitud
    selected_year = request.args.get('year', 'todos')
    selected_month = request.args.get('month', 'todos')

    # Consulta base: Unir Gasto y Titular
    query = Gasto.query.join(Titular, Gasto.titular_cedula == Titular.cedula)

    # Filtrado por año y mes (lo gestiona el frontend, pero lo simulamos aquí si es necesario)
    # Nota: Tu frontend ya filtra la lista completa de gastos. Aquí solo devolvemos la lista completa
    # y los datos agregados para los gráficos (que también usaremos la lista completa por simplicidad).
    
    # Para el cálculo consolidado, usaremos la lista de gastos ya obtenida en /reportes/gastos 
    # o podríamos hacer la agregación aquí. Por eficiencia, haremos la agregación directamente.

    gastos = query.all()
    
    # 1. Agregación de datos
    total_gastos_bs = 0
    vicerrectorado_data = {}
    condicion_data = {}
    tipo_gasto_data = {}
    diagnostico_data = {}
    
    # Agregación para gráficos
    for gasto in gastos:
        # Aquí puedes aplicar el filtro de año/mes si quieres que el backend haga el filtrado antes de la agregación.
        # Si no aplicas el filtro aquí, el frontend debe filtrar la lista completa que recibe.
        
        # Simulamos el filtro para la agregación, si está presente
        gasto_date = datetime.strptime(gasto.fecha_gasto, '%Y-%m-%d')
        
        year_match = (selected_year == 'todos' or str(gasto_date.year) == selected_year)
        month_match = (selected_month == 'todos' or str(gasto_date.month) == selected_month)

        if year_match and month_match:
            monto = gasto.monto
            total_gastos_bs += monto
            
            # Datos de Titular
            titular = Titular.query.filter_by(cedula=gasto.titular_cedula).first()
            if titular:
                # Agregación por Vicerrectorado
                vpds = titular.vicerrectorado
                vicerrectorado_data[vpds] = vicerrectorado_data.get(vpds, 0) + monto
                
                # Agregación por Condición
                cond = titular.condicion
                condicion_data[cond] = condicion_data.get(cond, 0) + monto
                
                # Agregación por Tipo de Gasto
                tipo = gasto.tipo_gasto
                tipo_gasto_data[tipo] = tipo_gasto_data.get(tipo, 0) + monto
                
                # Agregación por Diagnóstico (Conteo)
                diag = gasto.diagnostico
                diagnostico_data[diag] = diagnostico_data.get(diag, 0) + 1
    
    # 2. Devolver la respuesta (El cálculo USD se hace en el frontend con la tasa actual)
    return jsonify({
        "total_gastos_bs": total_gastos_bs,
        "vicerrectorado_data": vicerrectorado_data,
        "condicion_data": condicion_data,
        "tipo_gasto_data": tipo_gasto_data,
        "diagnostico_data": diagnostico_data
    }), 200
# --- Ejecutar la Aplicación ---
if __name__ == '__main__':
    app.run(debug=True)