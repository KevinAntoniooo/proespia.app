from flask import Flask, render_template, request, redirect, url_for, flash, make_response, Response, jsonify, send_file, session
from models import db, Usuario, Equipo, Cliente, Bitacora, Boveda, VisitaProgramada, CategoriaItem, Ubicacion, ProductoStock, MovimientoStock, Vehiculo, Herramienta, ChecklistSemanal, PushSubscription, Notificacion, SolicitudCombustible, RegistroIP, SUPER_ADMIN_CORREO
from datetime import datetime, time, timedelta, date
from sqlalchemy.exc import IntegrityError
from fpdf import FPDF
from sqlalchemy import func, case, or_, and_
import io
import unicodedata
import os
import re
import secrets
import functools
from werkzeug.utils import secure_filename
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from models import get_fernet
import json
import locale
import time
try:
    import requests
except ImportError:
    requests = None

os.environ['TZ'] = 'America/Santiago'
if hasattr(time, 'tzset'):
    time.tzset()
from base64 import b64encode, b64decode

# ==========================================
# 0. CONFIGURACIÓN E INICIALIZACIÓN DE LA APP
# ==========================================
# Configura el sistema en español para las fechas (Chile o estándar)
# Configura el sistema en español para las fechas (fallback silencioso si no hay locale)
for _locale in ['es_CL.UTF-8', 'es_CL', 'Spanish_Chile.1252', 'en_US.UTF-8', '']:
    try:
        locale.setlocale(locale.LC_TIME, _locale)
        break
    except locale.Error:
        continue
app = Flask(__name__) # <--- PRIMERO CREAMOS LA APP

# Filtro Jinja para parsear JSON desde string
@app.template_filter('fromjson')
def fromjson_filter(value):
    if not value:
        return []
    try:
        return json.loads(value)
    except Exception:
        return []

# PostgreSQL for production (Render), SQLite for local dev
_db_url = os.environ.get('DATABASE_URL', 'sqlite:///database.db')
if _db_url.startswith('postgres://'):
    _db_url = _db_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = _db_url
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'proespiapt_seguridad_2026')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=15)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=15)
# VAPID keys para Web Push Notifications (generadas con py-vapid)
app.config['VAPID_PRIVATE_KEY'] = 'EBTOb_kaWp7FPYpGZcV8r_fegUJENKcoI6adDZ0scAY'
app.config['VAPID_PUBLIC_KEY'] = 'BMz3vT_Sq1q8-xozy7P6CG28HABJhJBm_eGAIWvUpSMuFz2AUVMkQ83E_rQrIZha5m2fDsDltT5c8SK8ozA_Ot0'
app.config['VAPID_CLAIM_EMAIL'] = 'mailto:contacto@proespia.cl'
# Configuración de cookies de sesión persistente
app.config['SESSION_COOKIE_NAME'] = 'proespia_session'
# Configuración de Fernet (cifrado simétrico para Bóveda)
FERNET_KEY = get_fernet(app)
# Configuración de subida de archivos
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'static', 'uploads')

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Inicializamos la DB
db.init_app(app)

# ==========================================
# 1. CONFIGURACIÓN DE FLASK-LOGIN (Ahora app ya existe)
# ==========================================
login_manager = LoginManager()
login_manager.init_app(app) # <--- AHORA S�? FUNCIONA
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))

@login_manager.unauthorized_handler
def _unauth():
    if current_user.is_authenticated:
        return redirect(url_for('espera'))
    return redirect(url_for('login'))

# ==========================================
# 1.1 HELPERS DE AUTENTICACIÓN Y SEGURIDAD
# ==========================================
RUTAS_LIBRES = {'login', 'registro', 'login_google', 'login_google_callback',
                'olvido_contrasena', 'restablecer_password', 'static', 'service_worker',
                'manifest_json'}

def get_client_ip():
    fwd = request.headers.get('X-Forwarded-For', '')
    if fwd:
        return fwd.split(',')[0].strip()
    return request.remote_addr or '0.0.0.0'

def throttling_ip(ip, ventana_minutos=15, max_intentos=3):
    """Incrementa / limpia / bloquea según la cantidad de registros por IP."""
    from datetime import timedelta as _td
    ahora = datetime.now()
    limite = ahora - _td(minutes=ventana_minutos)
    registro = RegistroIP.query.filter_by(ip_address=ip).first()
    if not registro:
        registro = RegistroIP(ip_address=ip, intentos=1, ultima_accion=ahora)
        db.session.add(registro)
        db.session.commit()
        return True
    if registro.ultima_accion < limite:
        registro.intentos = 1
        registro.ultima_accion = ahora
        db.session.commit()
        return True
    if registro.intentos >= max_intentos:
        return False
    registro.intentos += 1
    registro.ultima_accion = ahora
    db.session.commit()
    return True

def reset_throttling_ip(ip):
    RegistroIP.query.filter_by(ip_address=ip).delete()
    db.session.commit()

def correo_valido(correo):
    if not correo:
        return False
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", correo.strip()))

def es_super_admin_email(correo):
    return (correo or '').strip().lower() == SUPER_ADMIN_CORREO

def require_active_user(view):
    """Decorador: bloquea acceso al dashboard a Pendientes / Inactivos."""
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        if not current_user.puede_acceder():
            return redirect(url_for('espera'))
        return view(*args, **kwargs)
    return wrapper

def requiere_admin(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        if current_user.rol not in ('admin', 'super_su'):
            flash('Acceso restringido a administradores.', 'danger')
            return redirect(url_for('dashboard', user_id=current_user.id))
        if not current_user.puede_acceder():
            return redirect(url_for('espera'))
        return view(*args, **kwargs)
    return wrapper

def obtener_google_config():
    return {
        'client_id': os.environ.get('GOOGLE_CLIENT_ID', ''),
        'client_secret': os.environ.get('GOOGLE_CLIENT_SECRET', ''),
        'redirect_uri': url_for('login_google_callback', _external=True),
    }

@app.before_request
def _muro_contencion_global():
    """Si el usuario está autenticado pero es Pendiente / Inactivo,
    solo puede acceder a /espera, /logout y a endpoints públicos."""
    if not current_user.is_authenticated:
        return None
    if current_user.puede_acceder():
        return None
    endpoint = request.endpoint or ''
    permitidos = {'espera', 'logout', 'static', 'service_worker', 'manifest_json'}
    if endpoint in permitidos:
        return None
    if endpoint.startswith('static'):
        return None
    return redirect(url_for('espera'))

def vapid_public_b64():
    """La clave pública ya está en formato raw base64url que necesita el navegador."""
    return app.config['VAPID_PUBLIC_KEY']

@app.context_processor
def inject_globals():
    ctx = dict(VAPID_PUBLIC_KEY_B64=vapid_public_b64())
    try:
        if current_user.is_authenticated:
            ctx['pendientes_fallas'] = Bitacora.query.filter(
                Bitacora.tipo_visita.ilike('%Falla%'),
                ~Bitacora.tipo_visita.ilike('%RESUELTA%')
            ).count()
            if current_user.rol in ['admin', 'super_su']:
                ctx['pendientes_visitas'] = VisitaProgramada.query.filter(
                    VisitaProgramada.estado == 'Pendiente',
                    VisitaProgramada.falla_id.is_(None)
                ).count()
            elif current_user.rol == 'tecnico':
                ctx['pendientes_visitas'] = VisitaProgramada.query.filter(
                    VisitaProgramada.estado == 'Pendiente',
                    or_(
                        VisitaProgramada.usuario_id == current_user.id,
                        VisitaProgramada.falla_id.isnot(None)
                    )
                ).count()
            else:
                ctx['pendientes_visitas'] = 0
    except Exception:
        pass
    return ctx

# ==========================================
# 2. FUNCIONES DE APOYO (HELPERS)
# ==========================================
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    if not filename or '.' not in filename:
        return False
    extension = filename.rsplit('.', 1)[1].lower()
    return extension in ALLOWED_EXTENSIONS

def limpiar_pdf(texto):
    if not texto: return ""
    texto = ''.join(c for c in unicodedata.normalize('NFD', str(texto))
                  if unicodedata.category(c) != 'Mn')
    return texto.encode('latin-1', 'ignore').decode('latin-1')

# ==========================================
# 2. SERVICE WORKER Y PWA
# ==========================================

@app.route('/sw.js')
def service_worker():
    response = app.send_static_file('sw.js')
    response.headers['Content-Type'] = 'application/javascript'
    response.headers['Cache-Control'] = 'no-cache'
    return response

@app.route('/manifest.json')
def manifest_json():
    response = app.send_static_file('manifest.json')
    response.headers['Content-Type'] = 'application/json'
    response.headers['Cache-Control'] = 'no-cache'
    return response

# ==========================================
# 3. RUTAS DE ACCESO (LOGIN)
# ==========================================

@app.route('/', methods=['GET', 'POST'])
def login():
    # 1. Redirección automática si ya hay sesión activa
    if current_user.is_authenticated:
        if current_user.puede_acceder():
            return redirect(url_for('dashboard', user_id=current_user.id))
        return redirect(url_for('espera'))

    if request.method == 'POST':
        usuario_ingresado = request.form.get('usuario', '').strip()
        password_ingresado = request.form.get('password', '')
        remember = True if request.form.get('remember') else False

        user = Usuario.query.filter(
            or_(
                Usuario.username == usuario_ingresado.lower(),
                func.lower(Usuario.correo) == usuario_ingresado.lower()
            )
        ).first()

        if user and user.check_password(password_ingresado):
            if user.estado != 'Activo':
                flash('Cuenta desactivada. Contacta a la jefatura.', 'warning')
                return redirect(url_for('login'))
            login_user(user, remember=remember)
            session.permanent = bool(remember)
            if not user.puede_acceder():
                flash('Tu cuenta está en trámite de activación.', 'info')
                return redirect(url_for('espera'))
            flash(f'Bienvenido de nuevo, {user.nombre}', 'success')
            return redirect(url_for('dashboard', user_id=user.id))

        flash('Credenciales incorrectas. Por favor, verifique sus datos.', 'warning')

    return render_template('login.html')

# ==========================================
# 3.1 REGISTRO DE NUEVOS USUARIOS (CORREO + CONTRASEÑA)
# ==========================================
@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if current_user.is_authenticated:
        return redirect(url_for('espera') if not current_user.puede_acceder() else url_for('dashboard', user_id=current_user.id))

    if request.method == 'POST':
        ip = get_client_ip()
        if not throttling_ip(ip):
            return jsonify({'ok': False, 'msg': 'Demasiados intentos desde tu red. Intenta en 15 minutos.'}), 429

        # Acepta form data o JSON
        if request.is_json:
            data = request.get_json(silent=True) or {}
        else:
            data = request.form
        nombre = (data.get('nombre') or '').strip()
        correo = (data.get('correo') or '').strip().lower()
        password = data.get('password') or ''
        password2 = data.get('password2') or ''

        if not nombre or not correo or not password:
            return jsonify({'ok': False, 'msg': 'Todos los campos son obligatorios.'}), 400
        if not correo_valido(correo):
            return jsonify({'ok': False, 'msg': 'El correo no es válido.'}), 400
        if len(password) < 6:
            return jsonify({'ok': False, 'msg': 'La contraseña debe tener al menos 6 caracteres.'}), 400
        if password != password2:
            return jsonify({'ok': False, 'msg': 'Las contraseñas no coinciden.'}), 400

        existente = Usuario.query.filter(func.lower(Usuario.correo) == correo).first()
        if existente:
            return jsonify({'ok': False, 'msg': 'Este correo ya está registrado.'}), 409

        try:
            username = correo.split('@')[0]
            base_username = re.sub(r'[^a-z0-9._-]', '', username.lower()) or 'usuario'
            username_unico = base_username
            i = 1
            while Usuario.query.filter_by(username=username_unico).first():
                username_unico = f"{base_username}{i}"
                i += 1

            rol_inicial = 'admin' if correo == SUPER_ADMIN_CORREO else 'Pendiente'

            nuevo = Usuario(
                nombre=nombre,
                username=username_unico,
                correo=correo,
                rol=rol_inicial,
                estado='Activo',
            )
            nuevo.set_password(password)
            db.session.add(nuevo)
            db.session.commit()

            reset_throttling_ip(ip)
            login_user(nuevo)

            if nuevo.rol == 'Pendiente':
                return jsonify({'ok': True, 'redirect': url_for('espera')})
            return jsonify({'ok': True, 'redirect': url_for('dashboard', user_id=nuevo.id)})
        except IntegrityError:
            db.session.rollback()
            return jsonify({'ok': False, 'msg': 'Conflicto de datos. Intenta con otro correo.'}), 409
        except Exception as e:
            db.session.rollback()
            print(f"Error en registro: {e}")
            return jsonify({'ok': False, 'msg': 'Error técnico al registrar. Intenta más tarde.'}), 500

    return render_template('registro.html')

# ==========================================
# 3.2 LOGIN CON GOOGLE OAUTH 2.0 (DESHABILITADO — solo correo+contraseña)
# ==========================================
GOOGLE_LOGIN_ENABLED = False

@app.route('/login/google', methods=['POST'])
def login_google():
    if not GOOGLE_LOGIN_ENABLED:
        return jsonify({'ok': False, 'msg': 'El inicio de sesión con Google está deshabilitado. Usa tu correo y contraseña.'}), 403
    ip = get_client_ip()
    if not throttling_ip(ip):
        return jsonify({'ok': False, 'msg': 'Demasiados intentos. Intenta en 15 minutos.'}), 429

    credential = (request.get_json() or {}).get('credential', '')
    if not credential:
        return jsonify({'ok': False, 'msg': 'Token de Google no recibido.'}), 400

    cfg = obtener_google_config()
    if not cfg['client_id'] or not requests:
        return jsonify({'ok': False, 'msg': 'Google Login no configurado en el servidor.'}), 501

    try:
        r = requests.get(
            'https://oauth2.googleapis.com/tokeninfo',
            params={'id_token': credential},
            timeout=6
        )
        if r.status_code != 200:
            return jsonify({'ok': False, 'msg': 'Token de Google inválido.'}), 401
        info = r.json()
    except Exception as e:
        print(f"Error validando Google: {e}")
        return jsonify({'ok': False, 'msg': 'No se pudo verificar Google en este momento.'}), 502

    google_id = info.get('sub')
    correo = (info.get('email') or '').strip().lower()
    nombre = info.get('name') or (correo.split('@')[0] if correo else 'Usuario Google')
    correo_verificado = info.get('email_verified') in ('true', True, 1)

    if not google_id or not correo or not correo_verificado:
        return jsonify({'ok': False, 'msg': 'Cuenta de Google no verificada.'}), 401

    if not cfg['client_id'] or info.get('aud') != cfg['client_id']:
        return jsonify({'ok': False, 'msg': 'Token de Google no autorizado para esta app.'}), 401

    user = Usuario.query.filter(
        or_(
            func.lower(Usuario.correo) == correo,
            Usuario.google_id == google_id
        )
    ).first()

    if not user:
        try:
            username_base = re.sub(r'[^a-z0-9._-]', '', correo.split('@')[0].lower()) or 'guser'
            username = username_base
            i = 1
            while Usuario.query.filter_by(username=username).first():
                username = f"{username_base}{i}"
                i += 1
            rol_inicial = 'admin' if correo == SUPER_ADMIN_CORREO else 'Pendiente'
            user = Usuario(
                nombre=nombre,
                username=username,
                correo=correo,
                google_id=google_id,
                rol=rol_inicial,
                estado='Activo',
            )
            db.session.add(user)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"Error creando usuario Google: {e}")
            return jsonify({'ok': False, 'msg': 'No se pudo crear la cuenta con Google.'}), 500

    elif not user.google_id:
        user.google_id = google_id
        db.session.commit()

    if user.estado != 'Activo':
        return jsonify({'ok': False, 'msg': 'Cuenta desactivada. Contacta a la jefatura.'}), 403

    reset_throttling_ip(ip)
    login_user(user)
    if user.rol == 'Pendiente':
        return jsonify({'ok': True, 'redirect': url_for('espera')})
    return jsonify({'ok': True, 'redirect': url_for('dashboard', user_id=user.id)})

@app.route('/login/google/callback')
def login_google_callback():
    if not GOOGLE_LOGIN_ENABLED:
        flash('El inicio de sesión con Google está deshabilitado.', 'info')
    return redirect(url_for('login'))

# ==========================================
# 3.3 RECUPERACIÓN DE CONTRASEÑA
# ==========================================
@app.route('/olvido_contrasena', methods=['GET', 'POST'])
def olvido_contrasena():
    if request.method == 'POST':
        correo = (request.form.get('correo') or '').strip().lower()
        if not correo_valido(correo):
            flash('Ingresa un correo válido.', 'warning')
            return redirect(url_for('olvido_contrasena'))

        user = Usuario.query.filter(func.lower(Usuario.correo) == correo).first()
        if user and not user.google_id:
            token = secrets.token_urlsafe(32)
            user.token_recuperacion = token
            db.session.commit()
            enlace = url_for('restablecer_password', token=token, _external=True)
            print(f"\n==================================================")
            print(f"[RECUPERACIÓN DE CONTRASEÑA]")
            print(f"Usuario: {user.nombre} <{user.correo}>")
            print(f"Enlace:  {enlace}")
            print(f"==================================================\n")

        flash('Si el correo existe en el sistema, te enviamos un enlace de recuperación.', 'info')
        return redirect(url_for('login'))

    return render_template('olvido_contrasena.html')

@app.route('/restablecer_password/<token>', methods=['GET', 'POST'])
def restablecer_password(token):
    user = Usuario.query.filter_by(token_recuperacion=token).first()
    if not user:
        flash('El enlace de recuperación es inválido o ya fue utilizado.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        nueva = request.form.get('password') or ''
        nueva2 = request.form.get('password2') or ''
        if len(nueva) < 6:
            flash('La nueva contraseña debe tener al menos 6 caracteres.', 'warning')
            return redirect(url_for('restablecer_password', token=token))
        if nueva != nueva2:
            flash('Las contraseñas no coinciden.', 'warning')
            return redirect(url_for('restablecer_password', token=token))

        user.set_password(nueva)
        user.token_recuperacion = None
        db.session.commit()
        flash('Contraseña actualizada con éxito. Ya puedes iniciar sesión.', 'success')
        return redirect(url_for('login'))

    return render_template('restablecer_password.html', token=token, user=user)

# ==========================================
# 3.4 MURO DE CONTENCIÓN (/espera) — CSS PURO
# ==========================================
@app.route('/espera')
def espera():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    if current_user.puede_acceder():
        return redirect(url_for('dashboard', user_id=current_user.id))
    return render_template('espera.html', usuario=current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ==========================================
# 3.5 WIPE TOTAL (solo Súper Admin autenticado + token de confirmación)
# ==========================================
@app.route('/admin/wipe_db', methods=['POST'])
@login_required
def admin_wipe_db():
    """Endpoint de un solo uso para limpiar la BD en producción.
    Requiere: (a) sesión activa del Súper Admin, (b) header X-Wipe-Token con valor
    del env var WIPE_TOKEN. Sin el token, devuelve 403."""
    if not current_user.es_super_admin() or not current_user.puede_acceder():
        return jsonify({'ok': False, 'msg': 'Solo el Súper Admin puede ejecutar esta acción.'}), 403

    expected = os.environ.get('WIPE_TOKEN', '')
    provided = request.headers.get('X-Wipe-Token', '')
    if not expected or provided != expected:
        return jsonify({'ok': False, 'msg': 'Token de confirmación inválido. Configura WIPE_TOKEN en el servidor.'}), 403

    try:
        from models import (
            Notificacion, PushSubscription, SolicitudCombustible, ChecklistSemanal,
            Herramienta, MovimientoStock, ProductoStock, Vehiculo, Ubicacion,
            CategoriaItem, VisitaProgramada, Boveda, Bitacora, Equipo, Cliente,
            Tarea, RegistroIP
        )
        tablas = [
            Notificacion, PushSubscription, SolicitudCombustible, ChecklistSemanal,
            Herramienta, MovimientoStock, ProductoStock, Vehiculo, Ubicacion,
            CategoriaItem, VisitaProgramada, Boveda, Bitacora, Equipo, Cliente,
            Tarea, RegistroIP
        ]
        resumen = {}
        for m in tablas:
            try:
                n = m.query.delete()
                resumen[m.__tablename__] = n
            except Exception as e:
                db.session.rollback()
                resumen[m.__tablename__] = f'err: {e}'

        usuarios_borrados = Usuario.query.filter(
            or_(
                Usuario.correo.is_(None),
                func.lower(Usuario.correo) != SUPER_ADMIN_CORREO
            )
        ).delete(synchronize_session=False)
        resumen['usuario (no super)'] = usuarios_borrados

        sa = Usuario.query.filter(func.lower(Usuario.correo) == SUPER_ADMIN_CORREO).first()
        if not sa:
            sa = Usuario(
                nombre='Kevin (Súper Admin)',
                username='kevix0813',
                correo=SUPER_ADMIN_CORREO,
                rol='admin',
                estado='Activo',
            )
            sa.set_password('ProEspia2026')
            db.session.add(sa)
        else:
            sa.password = generate_password_hash('ProEspia2026')
            sa.rol = 'admin'
            sa.estado = 'Activo'

        for nombre in ['Camaras', 'Conectividad', 'Discos Duros', 'Herramientas',
                       'Accesorios', 'Gabinetes', 'Fuentes de Poder', 'Cableado']:
            db.session.add(CategoriaItem(nombre=nombre))
        db.session.add(Ubicacion(nombre='Bodega Central', color='primary'))

        db.session.commit()
        return jsonify({'ok': True, 'msg': 'BD limpiada. Login: kevix0813@yahoo.es / ProEspia2026', 'resumen': resumen})
    except Exception as e:
        db.session.rollback()
        return jsonify({'ok': False, 'msg': str(e)}), 500

# ==========================================
# 4. DASHBOARD PRINCIPAL
# ==========================================
from datetime import datetime, time, date

@app.route('/dashboard/<int:user_id>')
@require_active_user
def dashboard(user_id):
    # Usamos la forma moderna para obtener el usuario
    usuario = db.session.get(Usuario, user_id)
    
    # Fecha de hoy y rangos para evitar fallos de SQLite
    hoy_date = date.today()
    inicio_hoy = datetime.combine(hoy_date, time.min)
    fin_hoy = datetime.combine(hoy_date, time.max)

    # --- LÓGICA PARA EL TÉCNICO ---
    if usuario.rol == 'tecnico':
        # 1. Visitas para HOY que estén Pendientes (incluye fallas)
        visitas_hoy = VisitaProgramada.query.filter(
            VisitaProgramada.fecha_programada >= inicio_hoy,
            VisitaProgramada.fecha_programada <= fin_hoy,
            VisitaProgramada.estado == 'Pendiente',
            or_(
                VisitaProgramada.usuario_id == user_id,
                VisitaProgramada.falla_id.isnot(None)
            )
        ).order_by(VisitaProgramada.prioridad.asc(), VisitaProgramada.fecha_programada.asc()).all()

        # 2. Próximas Visitas (Mañana en adelante, excluye vencidas)
        VisitaProgramada.query.filter(
            or_(
                VisitaProgramada.usuario_id == user_id,
                VisitaProgramada.falla_id.isnot(None)
            ),
            VisitaProgramada.fecha_programada < inicio_hoy,
            VisitaProgramada.estado == 'Pendiente'
        ).update({VisitaProgramada.estado: 'Vencida'}, synchronize_session=False)
        hace_3_dias = datetime.combine(hoy_date - timedelta(days=3), time.min)
        VisitaProgramada.query.filter(
            or_(
                VisitaProgramada.usuario_id == user_id,
                VisitaProgramada.falla_id.isnot(None)
            ),
            VisitaProgramada.estado == 'Vencida',
            VisitaProgramada.fecha_programada < hace_3_dias
        ).delete(synchronize_session=False)
        db.session.commit()

        proximas = VisitaProgramada.query.filter(
            VisitaProgramada.fecha_programada > fin_hoy,
            VisitaProgramada.estado.in_(['Pendiente']),
            or_(
                VisitaProgramada.usuario_id == user_id,
                VisitaProgramada.falla_id.isnot(None)
            )
        ).order_by(VisitaProgramada.prioridad.asc(), VisitaProgramada.fecha_programada.asc()).limit(5).all()

        # 3. Fallas pendientes (todas, no solo las que creó el técnico)
        tareas_tecnico = Bitacora.query.filter(
            Bitacora.tipo_visita.ilike('%Falla%'),
            ~Bitacora.tipo_visita.ilike('%RESUELTA%')
        ).order_by(Bitacora.prioridad.asc(), Bitacora.fecha.desc()).all()

        vehiculo_tec = Vehiculo.query.filter(Vehiculo.ubicacion_id == usuario.ubicacion_id).first()
        es_viernes = (vehiculo_tec and hoy_date.weekday() == vehiculo_tec.dia_checklist) if vehiculo_tec else False
        checklist_ok_hoy = False
        checklist_ok_hoy_id = None
        if vehiculo_tec:
            ck_hoy = ChecklistSemanal.query.filter(
                ChecklistSemanal.vehiculo_id == vehiculo_tec.id,
                db.func.date(ChecklistSemanal.fecha_registro) == hoy_date.isoformat()
            ).first()
            checklist_ok_hoy = ck_hoy is not None
            checklist_ok_hoy_id = ck_hoy.id if ck_hoy else None
        return render_template('dashboard.html',
                               usuario=usuario,
                               visitas_hoy=visitas_hoy,
                               proximas=proximas,
                               tareas=tareas_tecnico,
                               es_viernes=es_viernes,
                               checklist_ok_hoy=checklist_ok_hoy,
                               checklist_ok_hoy_id=checklist_ok_hoy_id)

    # --- LÓGICA PARA EL ADMINISTRADOR / OPERADOR (El bloque que tenías en rojo) ---
    else:
        equipos = Equipo.query.all()
        clientes = [{'id': c.id, 'nombre': c.nombre} for c in Cliente.query.all()]

        # Tareas pendientes globales (Fallas de Bitácora)
        tareas_pendientes = Bitacora.query.filter(
            Bitacora.tipo_visita.ilike('%Falla%'),
            ~Bitacora.tipo_visita.ilike('%RESUELTA%')
        ).order_by(Bitacora.fecha.desc()).all()

        # --- Visitas vencidas: pasar a "Vencida" las Pendientes con fecha pasada (excluye fallas) ---
        VisitaProgramada.query.filter(
            VisitaProgramada.fecha_programada < inicio_hoy,
            VisitaProgramada.estado == 'Pendiente',
            VisitaProgramada.falla_id.is_(None)
        ).update({VisitaProgramada.estado: 'Vencida'}, synchronize_session=False)
        # Eliminar Vencidas con más de 3 días de antigüedad (excluye fallas)
        hace_3_dias = datetime.combine(hoy_date - timedelta(days=3), time.min)
        VisitaProgramada.query.filter(
            VisitaProgramada.estado == 'Vencida',
            VisitaProgramada.falla_id.is_(None),
            VisitaProgramada.fecha_programada < hace_3_dias
        ).delete(synchronize_session=False)
        db.session.commit()

        # Próximas Visitas para el admin (futuro, solo Pendientes y Vencidas)
        proximas = VisitaProgramada.query.filter(
            VisitaProgramada.fecha_programada > fin_hoy,
            VisitaProgramada.estado.in_(['Pendiente', 'Vencida'])
        ).order_by(VisitaProgramada.fecha_programada.asc()).limit(10).all()

        # Resumen de agenda semanal para el Admin (desde hoy en adelante)
        domingo = hoy_date + timedelta(days=(6 - hoy_date.weekday()))
        fin_semana = datetime.combine(domingo, time.max)
        agenda_semanal = VisitaProgramada.query.filter(
            VisitaProgramada.fecha_programada >= inicio_hoy,
            VisitaProgramada.fecha_programada <= fin_semana
        ).order_by(VisitaProgramada.fecha_programada.asc()).all()
        dias_semana = ['LUN','MAR','MIÉ','JUE','VIE','SÁB','DOM']
        agenda_por_dia = {}
        for v in agenda_semanal:
            dia = v.fecha_programada.weekday()
            agenda_por_dia.setdefault(dia, []).append(v)

        total_items = db.session.query(func.sum(ProductoStock.cantidad_actual)).scalar() or 0
        items_bodega = db.session.query(func.sum(ProductoStock.cantidad_actual)).join(
            Ubicacion, ProductoStock.ubicacion_id == Ubicacion.id
        ).filter(Ubicacion.nombre.like('%Central%')).scalar() or 0
        criticos = ProductoStock.query.filter(ProductoStock.cantidad_actual < ProductoStock.cantidad_minima).count()

        total_clientes = Cliente.query.count()
        total_equipos = Equipo.query.count()
        total_tecnicos = Usuario.query.filter_by(rol='tecnico').count()
        total_vehiculos = Vehiculo.query.count()

        ultimas_bitacoras = Bitacora.query.order_by(Bitacora.fecha.desc()).limit(5).all()
        solicitudes_combustible = SolicitudCombustible.query.filter_by(estado='Pendiente').order_by(SolicitudCombustible.created_at.desc()).all()

        return render_template('dashboard.html',
                               usuario=usuario,
                               equipos=equipos,
                               clientes=clientes,
                               tareas=tareas_pendientes,
                               proximas=proximas,
                               agenda_semanal=agenda_semanal,
                               agenda_por_dia=agenda_por_dia,
                               dias_semana=dias_semana,
                               total_clientes=total_clientes,
                               total_equipos=total_equipos,
                               total_tecnicos=total_tecnicos,
                               total_vehiculos=total_vehiculos,
                               stock_total=total_items,
                               stock_bodega=items_bodega,
                                stock_criticos=criticos,
                                 ultimas_bitacoras=ultimas_bitacoras,
                                 solicitudes_combustible=solicitudes_combustible,
                                 es_viernes=(hoy_date.weekday() == 4))
# NUEVA RUTA: Para que el técnico marque como realizada
@app.route('/finalizar_visita/<int:visita_id>', methods=['POST'])
@login_required
def finalizar_visita(visita_id):
    visita = VisitaProgramada.query.get_or_404(visita_id)
    
    # 1. Cambiamos el estado
    visita.estado = 'Realizada'
    
    # 2. Guardamos la nota si viene
    nota = request.form.get('nota', '').strip()
    if nota:
        visita.informe_tecnico = nota
    
    # 3. Manejamos el nombre del cliente de forma segura para el mensaje Flash
    # Si rel_cliente existe, usamos su nombre. Si no, ponemos "Cliente Nuevo"
    nombre_cliente = visita.rel_cliente.nombre if visita.rel_cliente else "Cliente Nuevo"
    
    try:
        db.session.commit()
        flash(f'¡Trabajo en {nombre_cliente} marcado como realizado!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error al guardar el estado: {str(e)}', 'danger')
    
    return redirect(request.referrer or url_for('gestor_visitas', user_id=visita.usuario_id))

@app.route('/agenda/finalizar_cotizacion/<int:visita_id>', methods=['POST'])
@login_required
def finalizar_cotizacion(visita_id):
    visita = VisitaProgramada.query.get_or_404(visita_id)
    visita.estado = 'Realizada'
    visita.fecha_completada = datetime.now()
    try:
        db.session.commit()
        return jsonify({'ok': True, 'msg': 'Visita marcada como realizada'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'ok': False, 'msg': str(e)}), 400

# RUTA PARA COMPLETAR VISITA CON INFORME (Instalación, Mantención, Reparación, Emergencia)
@app.route('/completar_visita/<int:visita_id>/<int:user_id>', methods=['GET', 'POST'])
@login_required
def completar_visita_form(visita_id, user_id):
    visita = VisitaProgramada.query.get_or_404(visita_id)
    usuario = Usuario.query.get_or_404(user_id)
    
    if request.method == 'POST':
        informe = request.form.get('informe')
        foto = request.files.get('foto')
        
        visita.informe_tecnico = informe
        visita.fecha_completada = datetime.now()
        visita.estado = 'Realizada'
        
        if foto and allowed_file(foto.filename):
            filename = f"visita_{visita_id}_{foto.filename}"
            foto.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            visita.foto_visita = filename
        
        try:
            db.session.commit()
            flash('Visita completada con éxito', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error al guardar: {str(e)}', 'danger')
        
        return redirect(url_for('gestor_visitas', user_id=user_id))
    
    return render_template('completar_visita.html', visita=visita, usuario=usuario)

@app.route('/reporte_visita_pdf/<int:visita_id>/<int:user_id>')
@login_required
def reporte_visita_pdf(visita_id, user_id):
    visita = VisitaProgramada.query.get_or_404(visita_id)
    u = Usuario.query.get_or_404(user_id)
    
    try:
        pdf = FPDF()
        pdf.add_page()
        
        pdf.set_font('helvetica', 'B', 22)
        pdf.set_text_color(220, 53, 69)
        pdf.cell(0, 15, 'PROESPIA LTDA', align='L', new_x="LMARGIN", new_y="NEXT")
        
        pdf.set_font('helvetica', 'B', 10)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, -15, f"OT #00{visita.id} | REPORTE DE VISITA", align='R', new_x="LMARGIN", new_y="NEXT")
        pdf.ln(15)
        
        pdf.set_text_color(0, 0, 0)
        pdf.set_font('helvetica', 'B', 11)
        pdf.cell(35, 8, 'CLIENTE:')
        pdf.set_font('helvetica', '', 11)
        pdf.cell(65, 8, limpiar_pdf(visita.rel_cliente.nombre if visita.rel_cliente else 'Cliente Nuevo'))
        
        pdf.set_font('helvetica', 'B', 11)
        pdf.cell(40, 8, 'FECHA PROG.:')
        pdf.set_font('helvetica', '', 11)
        pdf.cell(0, 8, visita.fecha_programada.strftime('%d/%m/%Y %H:%M'), new_x="LMARGIN", new_y="NEXT")

        pdf.set_font('helvetica', 'B', 11)
        pdf.cell(35, 8, 'TECNICO:')
        pdf.set_font('helvetica', '', 11)
        pdf.cell(65, 8, limpiar_pdf(u.nombre))
        
        pdf.set_font('helvetica', 'B', 11)
        pdf.cell(40, 8, 'TIPO:')
        pdf.set_font('helvetica', '', 11)
        pdf.cell(0, 8, limpiar_pdf(visita.tipo_trabajo), new_x="LMARGIN", new_y="NEXT")
        
        if visita.fecha_completada:
            pdf.set_font('helvetica', 'B', 11)
            pdf.cell(35, 8, 'FECHA CIERRE:')
            pdf.set_font('helvetica', '', 11)
            fc = visita.fecha_completada
            if isinstance(fc, str):
                fc = datetime.strptime(fc, '%Y-%m-%d %H:%M:%S.%f')
            pdf.cell(0, 8, fc.strftime('%d/%m/%Y %H:%M'), new_x="LMARGIN", new_y="NEXT")
        
        pdf.ln(10)
        
        pdf.set_fill_color(245, 245, 245)
        pdf.set_font('helvetica', 'B', 12)
        pdf.cell(0, 10, ' 1. DESCRIPCION DEL SERVICIO', fill=True, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)
        pdf.set_font('helvetica', '', 11)
        pdf.multi_cell(0, 7, limpiar_pdf(visita.descripcion or 'Sin descripcion'))
        pdf.ln(8)
        
        pdf.set_fill_color(232, 245, 233)
        pdf.set_font('helvetica', 'B', 12)
        pdf.cell(0, 10, ' 2. INFORME TECNICO', fill=True, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)
        pdf.set_font('helvetica', '', 11)
        informe = visita.informe_tecnico if visita.informe_tecnico else 'No se registraron observaciones.'
        pdf.multi_cell(0, 7, limpiar_pdf(informe))
        
        if visita.foto_visita:
            pdf.ln(10)
            ruta_foto = os.path.join(app.config['UPLOAD_FOLDER'], visita.foto_visita)
            if os.path.exists(ruta_foto):
                pdf.set_font('helvetica', 'B', 12)
                pdf.cell(0, 10, ' 3. EVIDENCIA FOTOGRAFICA', new_x="LMARGIN", new_y="NEXT")
                pdf.image(ruta_foto, x=15, w=100)
        
        pdf.set_y(-50)
        pdf.set_font('helvetica', 'I', 8)
        pdf.cell(0, 10, 'Este documento es un comprobante oficial de PROESPIA LTDA - Seguridad Electronica.', align='C', new_x="LMARGIN", new_y="NEXT")
        
        pdf.ln(5)
        y_actual = pdf.get_y()
        pdf.line(30, y_actual + 15, 80, y_actual + 15)
        pdf.line(130, y_actual + 15, 180, y_actual + 15)
        pdf.set_font('helvetica', '', 9)
        pdf.text(40, y_actual + 20, "Firma Tecnico")
        pdf.text(140, y_actual + 20, "Recibe Conforme")
        
        pdf_output = pdf.output()
        return send_file(
            io.BytesIO(bytes(pdf_output)),
            mimetype='application/pdf',
            as_attachment=False,
            download_name=f"OT_Visita_{visita.id}.pdf"
        )
    except Exception as e:
        flash(f'Error al generar PDF: {str(e)}', 'danger')
        return redirect(url_for('gestor_visitas', user_id=user_id))

# RUTA GESTOR DE VISITAS (con tabs: agendadas, fallas pendientes, fallas realizadas)
@app.route('/gestor_visitas/<int:user_id>')
@login_required
def gestor_visitas(user_id):
    usuario = Usuario.query.get_or_404(user_id)

    inicio = request.args.get('fecha_inicio')
    fin = request.args.get('fecha_fin')
    filtros_fecha = []
    if inicio:
        filtros_fecha.append(VisitaProgramada.fecha_programada >= f"{inicio} 00:00:00")
    if fin:
        filtros_fecha.append(VisitaProgramada.fecha_programada <= f"{fin} 23:59:59")

    tecnicos = Usuario.query.filter_by(rol='tecnico').all() if usuario.rol in ['admin', 'super_su'] else []

    if usuario.rol in ['admin', 'super_su']:
        q_agendadas = VisitaProgramada.query.filter(VisitaProgramada.falla_id.is_(None))
        tecnico_id = request.args.get('tecnico_id', type=int)
        if tecnico_id:
            q_agendadas = q_agendadas.filter_by(usuario_id=tecnico_id)
        for f in filtros_fecha:
            q_agendadas = q_agendadas.filter(f)
        visitas_agendadas = q_agendadas.filter(VisitaProgramada.estado == 'Pendiente').order_by(
            VisitaProgramada.prioridad.asc(),
            VisitaProgramada.fecha_programada.desc()
        ).all()
        fallas_pendientes = []
        visitas_realizadas = []
    else:
        q_agendadas = VisitaProgramada.query.filter(
            VisitaProgramada.falla_id.is_(None),
            VisitaProgramada.usuario_id == user_id,
            VisitaProgramada.estado == 'Pendiente'
        )
        q_fallas_pend = VisitaProgramada.query.filter(
            VisitaProgramada.falla_id.isnot(None),
            VisitaProgramada.estado == 'Pendiente'
        )
        q_realizadas = VisitaProgramada.query.filter(
            VisitaProgramada.estado == 'Realizada',
            or_(
                VisitaProgramada.usuario_id == user_id,
                VisitaProgramada.falla_id.isnot(None)
            )
        )
        for f in filtros_fecha:
            q_agendadas = q_agendadas.filter(f)
            q_fallas_pend = q_fallas_pend.filter(f)
            q_realizadas = q_realizadas.filter(f)
        visitas_agendadas = q_agendadas.order_by(
            VisitaProgramada.prioridad.asc(),
            VisitaProgramada.fecha_programada.desc()
        ).all()
        fallas_pendientes = q_fallas_pend.order_by(
            VisitaProgramada.prioridad.asc(),
            VisitaProgramada.fecha_programada.asc()
        ).all()
        visitas_realizadas = q_realizadas.order_by(
            VisitaProgramada.fecha_programada.desc()
        ).all()

    total_pendientes = len(visitas_agendadas) + len(fallas_pendientes)

    return render_template('gestor_visitas.html', usuario=usuario,
                           visitas_agendadas=visitas_agendadas,
                           fallas_pendientes=fallas_pendientes,
                           visitas_realizadas=visitas_realizadas,
                           total_pendientes=total_pendientes,
                           tecnicos=tecnicos,
                           clientes=Cliente.query.order_by(Cliente.nombre.asc()).all())

# ==========================================
# 4. GESTIÓN DE CLIENTES (SEDES) Y EQUIPOS
# ==========================================
@app.route('/clientes/<int:user_id>')
@login_required
def ver_clientes(user_id):
    usuario = Usuario.query.get_or_404(user_id)
    # Traemos todos los clientes de la base de datos
    todos_los_clientes = Cliente.query.all()
    # Enviamos los clientes y el usuario al template
    return render_template('clientes.html', clientes=todos_los_clientes, usuario=usuario)

# --- CREAR NUEVO CLIENTE ---
@app.route('/clientes/nuevo/<int:user_id>', methods=['GET', 'POST'])
@login_required
def nuevo_cliente(user_id):
    usuario = Usuario.query.get_or_404(user_id)
    
    if request.method == 'POST':
        try:
            nuevo = Cliente(
                nombre=request.form.get('nombre'),
                direccion=request.form.get('direccion'),
                plan_cuadrante=request.form.get('plan_cuadrante'),
                contacto_emergencia=request.form.get('contacto_emergencia'),
                estado_monitoreo=request.form.get('estado_monitoreo'),
                latitud=request.form.get('latitud', type=float),
                longitud=request.form.get('longitud', type=float)
            )
            db.session.add(nuevo)
            db.session.commit()
            flash(f'Sede "{nuevo.nombre}" registrada correctamente', 'success')
            return redirect(url_for('ver_clientes', user_id=user_id))
        except Exception as e:
            db.session.rollback()
            flash('Error al registrar la sede. Intente nuevamente.', 'danger')
            return redirect(url_for('nuevo_cliente', user_id=user_id))
        
            registrar_log(current_user.id, "SISTEMA: Nuevo cliente creado", 
                  f"Se registró el cliente {nuevo.nombre}")
    return render_template('nuevo_cliente.html', usuario=usuario)

# --- ELIMINAR SEDE ---
@app.route('/clientes/eliminar/<int:cliente_id>/<int:user_id>')
@login_required
def eliminar_cliente(cliente_id, user_id):
    cliente = Cliente.query.get_or_404(cliente_id)
    # VERIFICACIÓN TÉCNICA: 
    # Revisamos si la lista de equipos del cliente tiene algún elemento
    if len(cliente.equipos) > 0:
        # Si tiene equipos, lanzamos advertencia y bloqueamos el borrado
        flash(f'BLOQUEO DE SEGURIDAD: La sede "{cliente.nombre}" tiene {len(cliente.equipos)} equipos vinculados. Debes eliminarlos o reasignarlos antes de borrar la sede.', 'warning')
        return redirect(url_for('ver_clientes', user_id=user_id))
    
    # Si no tiene equipos, el borrado es seguro
    nombre_borrado = cliente.nombre
    db.session.delete(cliente)
    db.session.commit()
    
    flash(f'Sede "{nombre_borrado}" eliminada exitosamente.', 'danger')
    return redirect(url_for('ver_clientes', user_id=user_id))

# --- EDITAR SEDE (POST) ---
@app.route('/clientes/editar/<int:cliente_id>/<int:user_id>', methods=['POST'])
@login_required
def editar_cliente(cliente_id, user_id):
    cliente = Cliente.query.get_or_404(cliente_id)
    
    # Actualizamos los campos con lo que viene del formulario
    cliente.nombre = request.form.get('nombre')
    cliente.direccion = request.form.get('direccion')
    cliente.plan_cuadrante = request.form.get('plan_cuadrante')
    cliente.contacto_emergencia = request.form.get('contacto_emergencia')
    cliente.estado_monitoreo = request.form.get('estado_monitoreo')
    cliente.latitud = request.form.get('latitud', type=float)
    cliente.longitud = request.form.get('longitud', type=float)
    
    try:
        db.session.commit()
        flash(f'Sede "{cliente.nombre}" actualizada con éxito.', 'success')

        # --- DISPARADOR: Cambio de estado de monitoreo ---
        if 'monitoreo' in (cliente.estado_monitoreo or '').lower():
            notificar_admin(
                'Cliente Activo en Central',
                f'{cliente.nombre} ahora está en MONITOREO. Verificar recepción de señales.',
                url_for('ver_clientes', user_id=user_id),
                tipo='exito',
                exclude_id=current_user.id
            )
    except Exception as e:
        db.session.rollback()
        flash('Error al actualizar los datos.', 'danger')
        
    return redirect(url_for('ver_clientes', user_id=user_id))

# --- CLIENTES Y REPORTES ---
@app.route('/clientes/reporte_pdf/<int:cliente_id>/<int:user_id>')
@login_required
def generar_pdf(cliente_id, user_id):
    cliente = Cliente.query.get_or_404(cliente_id)
    u_admin = Usuario.query.get_or_404(user_id)
    equipos = Equipo.query.filter_by(cliente_id=cliente_id).all()
    
    # Capturamos si el usuario marcó el checkbox
    incluir_pass = request.args.get('ver_pass') # Será 'on' si está marcado
    
    pdf = FPDF(orientation='P', unit='mm', format='A4')
    pdf.add_page()
    
    def t(texto):
        if not texto: return "N/A"
        return str(texto).encode('latin-1', 'replace').decode('latin-1')

    # --- ENCABEZADO ---
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(0, 10, t('PROESPIA LTDA - INVENTARIO TECNICO'), 0, 1, 'C')
    pdf.set_font('Arial', '', 12)
    pdf.cell(0, 8, t(f'Cliente: {cliente.nombre}'), 0, 1, 'C')
    pdf.set_font('Arial', '', 9)
    pdf.cell(0, 5, t(f'Direccion: {cliente.direccion}'), 0, 1, 'C')
    pdf.set_font('Arial', 'I', 9)
    pdf.cell(0, 5, f'Generado por: {t(u_admin.nombre)}', 0, 1, 'C')
    pdf.cell(0, 5, f'Fecha: {datetime.now().strftime("%d/%m/%Y %H:%M")}', 0, 1, 'C')
    pdf.ln(10)

    # --- TABLA DE EQUIPOS (Ajustamos anchos para la nueva columna) ---
    pdf.set_font('Arial', 'B', 9)
    pdf.set_fill_color(40, 40, 40)
    pdf.set_text_color(255, 255, 255)
    
    # Anchos ajustados: Tipo(35), Serie(55), IP(35), Usuario(30), Pass(35) = 190mm
    pdf.cell(35, 10, 'TIPO', 1, 0, 'C', True)
    pdf.cell(55, 10, 'SERIE (S/N)', 1, 0, 'C', True)
    pdf.cell(35, 10, 'IP', 1, 0, 'C', True)
    pdf.cell(30, 10, 'USUARIO', 1, 0, 'C', True)
    pdf.cell(35, 10, 'PASSWORD', 1, 1, 'C', True)

    pdf.set_text_color(0, 0, 0)
    pdf.set_font('Arial', '', 8) # Bajamos un poco la letra para que quepa todo
    for e in equipos:
        pdf.cell(35, 10, t(e.tipo), 1, 0, 'C')
        pdf.cell(55, 10, t(e.serie), 1, 0, 'C')
        pdf.cell(35, 10, t(e.ip), 1, 0, 'C')
        pdf.cell(30, 10, t(e.usuario_equipo), 1, 0, 'C')
        
        # Lógica del switch:
        if incluir_pass == 'on':
            pdf.cell(35, 10, t(e.pass_equipo), 1, 1, 'C')
        else:
            pdf.set_text_color(150, 150, 150) # Gris para lo oculto
            pdf.cell(35, 10, '********', 1, 1, 'C')
            pdf.set_text_color(0, 0, 0)

    # --- SALIDA ---
    output = io.BytesIO()
    pdf_output = pdf.output()
    output.write(pdf_output)
    output.seek(0)

    return make_response(output.read(), {
        'Content-Type': 'application/pdf',
        'Content-Disposition': f'inline; filename=Reporte_{cliente.nombre}.pdf'
    })
    
# ==========================================
# 5. GESTIÓN DE TAREAS Y FALLAS
# ==========================================
@app.route('/equipos/<int:user_id>')
@login_required
def ver_equipos(user_id):
    usuario = Usuario.query.get_or_404(user_id)
    equipos = Equipo.query.all()
    clientes = [{'id': c.id, 'nombre': c.nombre} for c in Cliente.query.all()]
    return render_template('equipos.html', equipos=equipos, usuario=usuario, clientes=clientes)

@app.route('/equipos/nuevo/<int:user_id>', methods=['GET', 'POST'])
@login_required
def nuevo_equipo(user_id):
    usuario = Usuario.query.get_or_404(user_id)
    
    if request.method == 'POST':
        try:
            nuevo = Equipo(
                cliente_id=request.form.get('cliente_id'),
                tipo=request.form.get('tipo'),
                serie=request.form.get('serie').strip().upper(), # Forzamos mayúsculas
                ip=request.form.get('ip'),
                usuario_equipo=request.form.get('usuario_equipo'),
                pass_equipo=request.form.get('pass_equipo')
            )
            db.session.add(nuevo)
            db.session.commit()
            flash('Equipo agregado al inventario', 'success')
            return redirect(url_for('ver_equipos', user_id=user_id))
        except IntegrityError:
            db.session.rollback()
            flash('Error: El número de serie ya existe', 'danger')
            return redirect(url_for('nuevo_equipo', user_id=user_id))
    
    clientes = [{'id': c.id, 'nombre': c.nombre} for c in Cliente.query.all()]
    return render_template('nuevo_equipo.html', clientes=clientes, usuario=usuario)

@app.route('/equipos/borrar/<int:equipo_id>/<int:user_id>')
@login_required
def borrar_equipo(equipo_id, user_id):
    equipo = Equipo.query.get_or_404(equipo_id)
    db.session.delete(equipo)
    db.session.commit()
    flash(f"Equipo eliminado correctamente.", "danger")
    return redirect(url_for('ver_equipos', user_id=user_id))

@app.route('/equipos/editar/<int:equipo_id>/<int:user_id>', methods=['POST'])
@login_required
def editar_equipo(equipo_id, user_id):
    equipo = Equipo.query.get_or_404(equipo_id)
    u_admin = Usuario.query.get_or_404(user_id)
    
    equipo.cliente_id = request.form.get('cliente_id')
    equipo.tipo = request.form.get('tipo')
    equipo.serie = request.form.get('serie').strip().upper()
    equipo.ip = request.form.get('ip')
    equipo.usuario_equipo = request.form.get('usuario_equipo')
    equipo.pass_equipo = request.form.get('pass_equipo')
    
    db.session.commit()
    flash('Equipo actualizado', 'success')
    return redirect(url_for('ver_equipos', user_id=user_id))

# ==========================================
# 6. GESTIÓN DE BITÁCORA (NOVEDADES, FALLAS, TAREAS)
# ==========================================
# 1. RUTA PARA VER EL LIBRO DE NOVEDADES
@app.route('/bitacora/<int:user_id>')
@login_required
def ver_bitacora(user_id):
    usuario = Usuario.query.get_or_404(user_id)
    page = request.args.get('page', 1, type=int)
    
    query = Bitacora.query

    inicio = request.args.get('fecha_inicio')
    fin = request.args.get('fecha_fin')
    if inicio and fin:
        query = query.filter(Bitacora.fecha >= f"{inicio} 00:00:00", 
                             Bitacora.fecha <= f"{fin} 23:59:59")
    
    # BITÁCORA: Orden cronológico puro (lo más nuevo arriba)
    paginado = query.order_by(Bitacora.fecha.desc(), Bitacora.id.desc()).paginate(page=page, per_page=20)
    
    return render_template('bitacora.html', 
                           usuario=usuario, 
                           registros=paginado.items, 
                           paginacion=paginado,
                           clientes=Cliente.query.all())
    
# 2. RUTA PARA GUARDAR UN SUCESO (CON PRIORIDAD)
@app.route('/bitacora/nueva/<int:user_id>', methods=['POST'])
@login_required
def nueva_entrada(user_id):
    c_id = request.form.get('cliente_id')
    suceso = request.form.get('tipo_suceso')
    desc = request.form.get('descripcion')
    fecha_str = request.form.get('fecha_suceso')
    prioridad_form = request.form.get('prioridad')
    
    try:
        # 1. Intentamos leer la fecha. Usamos una lógica flexible:
        if len(fecha_str) > 16:
            # Si el string tiene segundos (YYYY-MM-DDTHH:MM:SS)
            fecha_final = datetime.strptime(fecha_str, '%Y-%m-%dT%H:%M:%S')
        else:
            # Si no tiene segundos, los agregamos para que el orden sea exacto
            fecha_final = datetime.strptime(fecha_str, '%Y-%m-%dT%H:%M')
            ahora = datetime.now()
            fecha_final = fecha_final.replace(second=ahora.second, microsecond=ahora.microsecond)

        # 2. Lógica de prioridad
        sucesos_prioridad_fija = ['Incidente Crítico', 'Activación de Alarma', 'Ronda de Vigilancia', 'Apertura/Cierre Sede']
        
        if suceso in sucesos_prioridad_fija:
            prioridad_final = 1
        else:
            prioridad_final = int(prioridad_form) if prioridad_form else 3

        # 3. Guardar en DB
        nueva = Bitacora(
            cliente_id=int(c_id),
            tipo_visita=suceso, 
            descripcion=desc,
            usuario_id=user_id,
            fecha=fecha_final,
            prioridad=prioridad_final
        )
        
        db.session.add(nueva)
        db.session.commit()
        flash('Suceso registrado correctamente', 'success')

        # --- DISPARADOR: Crear VisitaProgramada si es falla ---
        if 'falla' in suceso.lower():
            cliente = Cliente.query.get(int(c_id))
            autor = Usuario.query.get(user_id)
            nom_cliente = cliente.nombre if cliente else 'Desconocido'

            visita = VisitaProgramada(
                cliente_id=int(c_id),
                usuario_id=current_user.id,
                tipo_trabajo='Reparación',
                descripcion=desc,
                estado='Pendiente',
                prioridad=prioridad_final,
                falla_id=nueva.id,
                fecha_programada=datetime.now()
            )
            db.session.add(visita)
            db.session.commit()
            flash(f'✓ Visita creada en Agenda de Terreno para {nom_cliente} (prioridad {prioridad_final})', 'success')

            notificar_admin(
                f'Falla Registrada - {nom_cliente}',
                f'{autor.nombre} registró una falla en {nom_cliente}',
                url_for('ver_bitacora', user_id=1),
                tipo='falla',
                exclude_id=current_user.id
            )
            notificar_tecnicos(
                f'Falla Pendiente - {nom_cliente}',
                f'Falla reportada en {nom_cliente}. Revisar terreno.',
                url_for('gestor_visitas', user_id=user_id) if 'gestor_visitas' in dir() else '/',
                tipo='falla'
            )

    except Exception as e:
        db.session.rollback()
        # Esto te ayudará a ver el error real si algo falla
        print(f"DEBUG ERROR: {str(e)}") 
        flash(f'Error al registrar: {str(e)}', 'danger')
        
    return redirect(url_for('ver_bitacora', user_id=user_id))

# 3. RUTA PARA GENERAR PDF DE LA BITÁCORA
@app.route('/bitacora/reporte_pdf/<int:user_id>')
@login_required
def reporte_bitacora_pdf(user_id):
    solicitante = Usuario.query.get_or_404(user_id)
    inicio = request.args.get('inicio')
    fin = request.args.get('fin')
    sede_id = request.args.get('sede_id', type=int)
    
    query = Bitacora.query
    if inicio and fin:
        query = query.filter(Bitacora.fecha >= f"{inicio} 00:00:00",
                             Bitacora.fecha <= f"{fin} 23:59:59")
    if sede_id:
        sede = Cliente.query.get(sede_id)
        query = query.filter(Bitacora.cliente_id == sede_id)
    else:
        sede = None
    registros = query.order_by(Bitacora.fecha.desc()).all()
    
    pdf = FPDF()
    pdf.add_page()
    
    # --- Encabezado ---
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(0, 10, "PROESPIA LTDA - SEGURIDAD ELECTRONICA", 0, 1, 'C')
    pdf.set_font("Arial", '', 10)
    pdf.cell(0, 10, f"REPORTE DE NOVEDADES{' ' + inicio + ' al ' + fin if inicio and fin else ' (todo el historial)'}{' - ' + sede.nombre if sede else ''}", 0, 1, 'C')
    pdf.ln(10)
    
    # --- Tabla de Datos ---
    pdf.set_fill_color(30, 30, 30) 
    pdf.set_text_color(255, 255, 255) 
    pdf.set_font("Arial", 'B', 9)
    
    # Añadimos columna de Prioridad al PDF para que el jefe vea qué fue lo más grave
    pdf.cell(30, 10, "FECHA", 1, 0, 'C', True)
    pdf.cell(40, 10, "SEDE", 1, 0, 'C', True)
    pdf.cell(40, 10, "SUCESO", 1, 0, 'C', True)
    pdf.cell(80, 10, "DESCRIPCION", 1, 1, 'C', True)
    
    pdf.set_text_color(0, 0, 0) 
    pdf.set_font("Arial", '', 8)
    
    for r in registros:
        pdf.cell(30, 8, r.fecha.strftime('%d/%m/%Y %H:%M'), 1)
        pdf.cell(40, 8, limpiar_pdf(r.rel_cliente.nombre[:22]), 1)
        pdf.cell(40, 8, limpiar_pdf(r.tipo_visita[:20]), 1)
        pdf.cell(80, 8, limpiar_pdf(r.descripcion[:55]), 1, 1)
        
    # --- PIE DE PÁGINA ---
    pdf.ln(10)
    pdf.set_font("Arial", 'I', 8)
    pdf.set_text_color(100, 100, 100)
    ahora = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
    pdf.cell(0, 5, f"Documento generado por: {limpiar_pdf(solicitante.nombre)}", 0, 1, 'R')
    pdf.cell(0, 5, f"Fecha de emision: {ahora}", 0, 1, 'R')
    
    pdf_output = pdf.output(dest='S')
    return Response(
        bytes(pdf_output),
        mimetype='application/pdf',
        headers={
            'Content-Disposition': f'inline; filename=Reporte_PROESPIA_{inicio}.pdf',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'
        }
    )

# 4. RUTA API PARA EL MODAL (AJAX)
@app.route('/api/bitacora/consulta')
def api_consulta_bitacora():
    inicio = request.args.get('inicio')
    fin = request.args.get('fin')
    sede_id = request.args.get('sede_id', type=int)

    query = Bitacora.query
    if inicio and fin:
        query = query.filter(Bitacora.fecha >= f"{inicio} 00:00:00",
                             Bitacora.fecha <= f"{fin} 23:59:59")
    if sede_id:
        query = query.filter(Bitacora.cliente_id == sede_id)
    registros = query.order_by(Bitacora.fecha.desc()).all()
    datos = []
    for r in registros:
        datos.append({
            'fecha': r.fecha.strftime('%d/%m/%Y %H:%M'),
            'sede': r.rel_cliente.nombre,
            'suceso': r.tipo_visita,
            'prioridad': r.prioridad
        })
    return {'sucesos': datos}

# ==========================================
# 6. GESTIÓN DE BÓVEDA DE CONTRASEÑAS (APPS, SERVICIOS, ETC)
# ==========================================
@app.route('/boveda/<int:user_id>', methods=['GET', 'POST'])
@login_required
def ver_boveda(user_id):
    usuario = Usuario.query.get_or_404(user_id)

    if request.method == 'POST':
        nombre = request.form.get('nombre_app')
        user_app = request.form.get('usuario_app')
        pass_app = request.form.get('password_app')
        encrypted_pass = Boveda.encrypt_password(pass_app)
        nueva_credencial = Boveda(
            nombre_app=nombre,
            url_acceso="",
            usuario_app=user_app,
            password_app=encrypted_pass,
            usuario_id=user_id
        )
        db.session.add(nueva_credencial)
        db.session.commit()
        flash('Credencial guardada con éxito', 'success')
        return redirect(url_for('ver_boveda', user_id=user_id))

    # Obtenemos las credenciales guardadas para este usuario
    aplicaciones = Boveda.query.filter_by(usuario_id=user_id).all()
    # Desencriptamos cada password para que el template pueda usarlo en modales de edicion
    for app in aplicaciones:
        app.password_app = app.decrypt_password()
    return render_template('boveda.html', usuario=usuario, aplicaciones=aplicaciones)

# RUTA PARA ELIMINAR UNA CREDENCIAL DE LA BÓVEDA
@app.route('/boveda/eliminar/<int:creden_id>/<int:user_id>')
@login_required
def eliminar_credencial(creden_id, user_id):
    credencial = Boveda.query.get_or_404(creden_id)
    
    # Seguridad: Solo el dueño puede borrarla
    if credencial.usuario_id == user_id:
        db.session.delete(credencial)
        db.session.commit()
        flash('Credencial eliminada correctamente', 'warning')
    else:
        flash('No tienes permiso para eliminar esta credencial', 'danger')
        
    return redirect(url_for('ver_boveda', user_id=user_id))

# RUTA PARA EDITAR UNA CREDENCIAL DE LA BÓVEDA (PROCESAR EL FORMULARIO)
@app.route('/boveda/editar/<int:creden_id>/<int:user_id>', methods=['POST'])
@login_required
def editar_credencial(creden_id, user_id):
    credencial = Boveda.query.get_or_404(creden_id)
    
    # Seguridad: Solo el dueño puede editar
    if credencial.usuario_id == user_id:
        credencial.nombre_app = request.form.get('nombre_app')
        credencial.usuario_app = request.form.get('usuario_app')
        plain_pass = request.form.get('password_app')
        credencial.password_app = Boveda.encrypt_password(plain_pass)
        
        db.session.commit()
        flash('Credencial actualizada con éxito', 'success')
    else:
        flash('No tienes permiso para editar esto', 'danger')
        
    return redirect(url_for('ver_boveda', user_id=user_id))

# RUTA AJAX PARA VERIFICAR CONTRASEÑA ADMIN Y DESENCRIPTAR CREDENCIAL
@app.route('/boveda/verificar_clave_admin', methods=['POST'])
@login_required
def verificar_clave_admin():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Solicitud invalida'}), 400

    password_ingresada = data.get('password_ingresada', '')
    creden_id = data.get('creden_id')

    if not current_user.check_password(password_ingresada):
        return jsonify({'error': 'Contrasena incorrecta'}), 401

    if not creden_id:
        return jsonify({'error': 'Credencial no especificada'}), 400

    credencial = Boveda.query.get(creden_id)
    if not credencial:
        return jsonify({'error': 'Credencial no encontrada'}), 404

    try:
        real_pass = credencial.decrypt_password()
    except Exception:
        return jsonify({'error': 'Error al desencriptar la credencial'}), 500

    return jsonify({'password': real_pass})

# ==========================================
# 7. GESTIÓN DE USUARIOS (SOLO PARA ADMINISTRADORES)
# ==========================================
@app.route('/usuarios/<int:user_id>', methods=['GET', 'POST'])
@requiere_admin
def gestionar_usuarios(user_id):
    usuario_admin = db.session.get(Usuario, user_id)

    if request.method == 'POST':
        nombre = request.form.get('nombre')
        username = (request.form.get('username') or '').strip().lower()
        correo = (request.form.get('correo') or '').strip().lower() or None
        rol = request.form.get('rol')
        ubicacion_id = request.form.get('ubicacion_id') or None
        password_plana = request.form.get('password')
        tipo_asignacion = request.form.get('tipo_asignacion', 'acompanante')

        if not nombre or not username or not password_plana:
            flash('Nombre, usuario y contraseña son obligatorios.', 'danger')
            return redirect(url_for('gestionar_usuarios', user_id=user_id))

        if correo:
            dup = Usuario.query.filter(func.lower(Usuario.correo) == correo).first()
            if dup:
                flash('Ya existe un usuario con ese correo.', 'danger')
                return redirect(url_for('gestionar_usuarios', user_id=user_id))

        try:
            nuevo = Usuario(
                nombre=nombre,
                username=username,
                correo=correo,
                rol=rol,
                estado='Activo',
                ubicacion_id=int(ubicacion_id) if ubicacion_id else None,
                tipo_asignacion=tipo_asignacion
            )
            nuevo.set_password(password_plana)
            db.session.add(nuevo)
            db.session.commit()
            flash(f'Personal "{nombre}" registrado correctamente.', 'success')
        except IntegrityError:
            db.session.rollback()
            flash('Conflicto: el nombre de usuario ya existe.', 'danger')
        except Exception as e:
            db.session.rollback()
            print(f"Error técnico al registrar: {e}")
            flash('No se pudo completar el registro.', 'danger')
        return redirect(url_for('gestionar_usuarios', user_id=user_id))

    usuarios = Usuario.query.order_by(Usuario.rol.asc(), Usuario.nombre.asc()).all()
    pendientes = Usuario.query.filter_by(rol='Pendiente').order_by(Usuario.created_at.desc()).all()
    ubicaciones = Ubicacion.query.order_by(Ubicacion.nombre.asc()).all()
    return render_template('usuarios.html',
                           usuarios=usuarios,
                           pendientes=pendientes,
                           usuario=usuario_admin,
                           ubicaciones=ubicaciones,
                           super_admin_correo=SUPER_ADMIN_CORREO)

# ==========================================
# 7.1 ACTIVAR / CAMBIAR ROL DE USUARIO (PENDIENTE → OPERATIVO)
# ==========================================
@app.route('/usuarios/activar/<int:target_id>/<int:admin_id>', methods=['POST'])
@requiere_admin
def activar_usuario(target_id, admin_id):
    u_target = Usuario.query.get_or_404(target_id)
    if u_target.es_super_admin():
        flash('El Súper Administrador es inmune. No se puede modificar.', 'danger')
        return redirect(url_for('gestionar_usuarios', user_id=admin_id))

    nuevo_rol = request.form.get('rol')
    if nuevo_rol not in ('admin', 'tecnico', 'operador'):
        flash('Rol no permitido.', 'danger')
        return redirect(url_for('gestionar_usuarios', user_id=admin_id))

    u_target.rol = nuevo_rol
    u_target.estado = 'Activo'
    db.session.commit()
    flash(f'{u_target.nombre} activado como {nuevo_rol.upper()}.', 'success')
    return redirect(url_for('gestionar_usuarios', user_id=admin_id))

@app.route('/usuarios/actualizar_completo/<int:target_id>/<int:admin_id>', methods=['POST'])
@requiere_admin
def actualizar_usuario_completo(target_id, admin_id):
    u_target = Usuario.query.get_or_404(target_id)

    nuevo_nombre = request.form.get('nombre')
    nuevo_username = (request.form.get('username') or '').strip().lower()
    nuevo_correo = (request.form.get('correo') or '').strip().lower() or None
    nuevo_rol = request.form.get('rol')
    nueva_pass = request.form.get('password')
    nueva_ubicacion_id = request.form.get('ubicacion_id') or None
    nuevo_tipo = request.form.get('tipo_asignacion', 'acompanante')

    # Inmunidad del súper admin: nadie le cambia correo, rol, ni estado
    if u_target.es_super_admin():
        if (nuevo_correo or '').lower() != SUPER_ADMIN_CORREO:
            flash('El Súper Administrador es inmune. No se puede modificar su correo.', 'danger')
            return redirect(url_for('gestionar_usuarios', user_id=admin_id))
        if nuevo_rol not in (None, '', 'admin'):
            flash('El Súper Administrador es inmune. No se puede cambiar su rol.', 'danger')
            return redirect(url_for('gestionar_usuarios', user_id=admin_id))

    conflicto_user = Usuario.query.filter(
        Usuario.username == nuevo_username,
        Usuario.id != target_id
    ).first()
    if conflicto_user:
        flash(f'Error: El usuario "@{nuevo_username}" ya está asignado.', 'danger')
        return redirect(url_for('gestionar_usuarios', user_id=admin_id))

    if nuevo_correo and not u_target.es_super_admin():
        dup_correo = Usuario.query.filter(
            func.lower(Usuario.correo) == nuevo_correo,
            Usuario.id != target_id
        ).first()
        if dup_correo:
            flash('Ese correo ya está en uso por otro usuario.', 'danger')
            return redirect(url_for('gestionar_usuarios', user_id=admin_id))

    try:
        u_target.nombre = nuevo_nombre
        u_target.username = nuevo_username
        if not u_target.es_super_admin():
            u_target.correo = nuevo_correo
        if not u_target.es_super_admin():
            u_target.rol = nuevo_rol
        u_target.ubicacion_id = int(nueva_ubicacion_id) if nueva_ubicacion_id else None
        u_target.tipo_asignacion = nuevo_tipo

        if nueva_pass and nueva_pass.strip():
            if target_id == admin_id:
                u_target.set_password(nueva_pass)
            else:
                flash("Solo puedes cambiar tu propia contraseña.", "danger")
                return redirect(url_for('gestionar_usuarios', user_id=admin_id))

        db.session.commit()
        flash(f"Datos de {u_target.nombre} actualizados con éxito", 'success')
    except Exception as e:
        db.session.rollback()
        print(f"Error en actualización: {e}")
        flash("Ocurrió un error técnico al intentar guardar los cambios.", "danger")

    return redirect(url_for('gestionar_usuarios', user_id=admin_id))

@app.route('/usuarios/cambiar_estado/<int:target_id>/<int:admin_id>', methods=['POST'])
@requiere_admin
def cambiar_estado_usuario(target_id, admin_id):
    u_target = Usuario.query.get_or_404(target_id)
    if u_target.es_super_admin():
        flash('El Súper Administrador es inmune. No se puede desactivar.', 'danger')
        return redirect(url_for('gestionar_usuarios', user_id=admin_id))
    nuevo_estado = request.form.get('estado')
    if nuevo_estado not in ('Activo', 'Inactivo'):
        flash('Estado inválido.', 'danger')
        return redirect(url_for('gestionar_usuarios', user_id=admin_id))
    u_target.estado = nuevo_estado
    db.session.commit()
    flash(f'{u_target.nombre} ahora está {nuevo_estado}.', 'warning' if nuevo_estado == 'Inactivo' else 'success')
    return redirect(url_for('gestionar_usuarios', user_id=admin_id))

@app.route('/usuarios/borrar/<int:target_id>/<int:admin_id>')
@requiere_admin
def borrar_usuario(target_id, admin_id):
    if target_id == admin_id:
        flash('No puedes borrar tu propia cuenta', 'danger')
        return redirect(url_for('gestionar_usuarios', user_id=admin_id))

    u_target = Usuario.query.get_or_404(target_id)
    if u_target.es_super_admin():
        flash('El Súper Administrador es inmune. No se puede eliminar.', 'danger')
        return redirect(url_for('gestionar_usuarios', user_id=admin_id))

    try:
        # Limpiar dependencias que apuntan al usuario (orden: hijos → padres)
        Notificacion.query.filter_by(usuario_id=target_id).delete(synchronize_session=False)
        PushSubscription.query.filter_by(usuario_id=target_id).delete(synchronize_session=False)
        SolicitudCombustible.query.filter_by(usuario_id=target_id).delete(synchronize_session=False)
        ChecklistSemanal.query.filter_by(usuario_id=target_id).delete(synchronize_session=False)
        MovimientoStock.query.filter_by(usuario_id=target_id).delete(synchronize_session=False)
        Boveda.query.filter_by(usuario_id=target_id).delete(synchronize_session=False)
        VisitaProgramada.query.filter_by(usuario_id=target_id).delete(synchronize_session=False)
        Bitacora.query.filter_by(usuario_id=target_id).delete(synchronize_session=False)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Error limpiando dependencias de usuario {target_id}: {e}")
        flash(f'No se pudo limpiar el historial del usuario: {str(e)[:120]}', 'danger')
        return redirect(url_for('gestionar_usuarios', user_id=admin_id))

    try:
        nombre = u_target.nombre
        db.session.delete(u_target)
        db.session.commit()
        flash(f'Usuario "{nombre}" eliminado permanentemente.', 'danger')
    except Exception as e:
        db.session.rollback()
        print(f"Error al eliminar usuario {target_id}: {e}")
        flash(f'No se pudo eliminar el usuario: {str(e)[:120]}', 'danger')

    return redirect(url_for('gestionar_usuarios', user_id=admin_id))
# ==========================================
# 8. GESTIÓN DE TAREAS PENDIENTES Y RESUELTAS
# ==========================================
@app.route('/tareas/<int:user_id>')
@login_required
def ver_todas_las_tareas(user_id):
    usuario = Usuario.query.get_or_404(user_id)
    page = request.args.get('page', 1, type=int)
    
    tipo_fecha = request.args.get('tipo_fecha', 'reporte')
    f_inicio = request.args.get('fecha_inicio')
    f_fin = request.args.get('fecha_fin')
    
    # 1. Filtro base: Buscamos fallas técnicas (pendientes y resueltas)
    # Usamos ilike para que capture tanto "Falla Técnica" como "Falla RESUELTA"
    query = Bitacora.query.filter(Bitacora.tipo_visita.ilike('%Falla%'))

    # 2. Aplicar filtros de fecha si existen
    if f_inicio and f_fin:
        date_start = datetime.combine(datetime.strptime(f_inicio, '%Y-%m-%d'), time.min)
        date_end = datetime.combine(datetime.strptime(f_fin, '%Y-%m-%d'), time.max)
        
        if tipo_fecha == 'reporte':
            query = query.filter(Bitacora.fecha.between(date_start, date_end))
        else:
            query = query.filter(Bitacora.fecha_resolucion.between(date_start, date_end))
    
    # 3. Paginación con el orden correcto:
    # Pendientes (0) primero, Resueltos (1) después. Luego por prioridad y fecha.
    paginado = query.order_by(
        case((Bitacora.fecha_resolucion == None, 0), else_=1),
        Bitacora.prioridad.asc(),
        Bitacora.fecha.desc()
    ).paginate(page=page, per_page=15) # 15 tareas por página

    return render_template('tareas_pendientes.html', 
                           tareas=paginado.items, 
                           paginacion=paginado, 
                           usuario=usuario,
                           hoy_iso=date.today().isoformat())
        
# RUTA PARA OBTENER LOS DETALLES DE UNA TAREA (AJAX)
@app.route('/api/tarea_detalle/<int:log_id>')
@login_required
def api_tarea_detalle(log_id):
    t = Bitacora.query.get_or_404(log_id)
    return jsonify({
        "sede": t.rel_cliente.nombre,
        "problema": t.descripcion,
        "informe": t.informe_tecnico,
        "foto": t.foto_falla,
        "fecha_resolucion": t.fecha_resolucion.strftime('%d/%m/%Y %H:%M') if t.fecha_resolucion else "",
        "usuario_id": t.usuario_id  # <--- AGREGAR ESTA LÍNEA
    })
@app.route('/completar_tarea/<int:log_id>/<int:user_id>', methods=['GET', 'POST'])
@login_required
def completar_tarea(log_id, user_id):
    tarea = Bitacora.query.get_or_404(log_id)
    usuario = Usuario.query.get_or_404(user_id)
    
    if request.method == 'POST':
        informe = request.form.get('informe') 
        foto = request.files.get('foto')
        
        tarea.informe_tecnico = informe
        tarea.fecha_resolucion = datetime.now()
        tarea.tipo_visita = "Falla RESUELTA" # Cambia estado para seguimiento
        
        if foto and allowed_file(foto.filename):
            filename = f"resuelto_{log_id}_{foto.filename}"
            foto.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            tarea.foto_falla = filename
            
        db.session.commit()
        
        # --- DISPARADOR: Falla resuelta ---
        cliente = tarea.rel_cliente
        nom_cliente = cliente.nombre if cliente else 'Desconocido'
        notificar_admin(
            'Falla Solucionada',
            f'{usuario.nombre} resolvió la falla en {nom_cliente}',
            url_for('ver_bitacora', user_id=1) if 'ver_bitacora' in dir() else '/',
            tipo='exito',
            exclude_id=current_user.id
        )
        notificar_operadores(
            'Falla Resuelta - Volver a Normalidad',
            f'El técnico {usuario.nombre} solucionó la falla en {nom_cliente}. Central ya recibe señales.',
            '/',
            tipo='exito',
            exclude_id=current_user.id
        )
        return redirect(url_for('ver_todas_las_tareas', user_id=user_id))
    
    return render_template('completar_tarea.html', log=tarea, usuario=usuario)
# RUTA PARA GENERAR PDF DE REPORTE DE FALLA (TAREA)
@app.route('/reporte_falla_pdf/<int:log_id>/<int:user_id>')
@login_required
def reporte_falla_pdf(log_id, user_id):
    log = Bitacora.query.get_or_404(log_id)
    u = Usuario.query.get_or_404(user_id)
    
    # Configuramos el PDF con la sintaxis moderna de fpdf2
    pdf = FPDF()
    pdf.add_page()
    
    # --- ENCABEZADO ---
    pdf.set_font('helvetica', 'B', 22)
    pdf.set_text_color(220, 53, 69) # Rojo PROESPIA LTDA
    pdf.cell(0, 15, 'PROESPIA LTDA', align='L', new_x="LMARGIN", new_y="NEXT")
    
    pdf.set_font('helvetica', 'B', 10)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, -15, f"OT #00{log.id} | REPORTE TECNICO", align='R', new_x="LMARGIN", new_y="NEXT")
    pdf.ln(15)
    
    # --- DATOS GENERALES ---
    pdf.set_text_color(0, 0, 0)
    pdf.set_font('helvetica', 'B', 11)
    pdf.cell(35, 8, 'CLIENTE:')
    pdf.set_font('helvetica', '', 11)
    pdf.cell(65, 8, limpiar_pdf(log.rel_cliente.nombre))
    
    pdf.set_font('helvetica', 'B', 11)
    pdf.cell(40, 8, 'FECHA REPORTE:')
    pdf.set_font('helvetica', '', 11)
    pdf.cell(0, 8, log.fecha.strftime('%d/%m/%Y %H:%M'), new_x="LMARGIN", new_y="NEXT")

    if log.fecha_resolucion:
        pdf.set_font('helvetica', 'B', 11)
        pdf.cell(35, 8, 'TECNICO:')
        pdf.set_font('helvetica', '', 11)
        pdf.cell(65, 8, limpiar_pdf(u.nombre))
        
        pdf.set_font('helvetica', 'B', 11)
        pdf.cell(40, 8, 'FECHA CIERRE:')
        pdf.set_font('helvetica', '', 11)
        pdf.cell(0, 8, log.fecha_resolucion.strftime('%d/%m/%Y %H:%M'), new_x="LMARGIN", new_y="NEXT")
    
    pdf.ln(10)
    
    # --- CUERPO DEL INFORME ---
    # Sección Problema
    pdf.set_fill_color(245, 245, 245)
    pdf.set_font('helvetica', 'B', 12)
    pdf.cell(0, 10, ' 1. DESCRIPCION DEL PROBLEMA', fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)
    pdf.set_font('helvetica', '', 11)
    pdf.multi_cell(0, 7, limpiar_pdf(log.descripcion))
    pdf.ln(8)
    
    # Sección Solución
    pdf.set_fill_color(232, 245, 233) # Verde clarito
    pdf.set_font('helvetica', 'B', 12)
    pdf.cell(0, 10, ' 2. SOLUCION APLICADA / ACCIONES TOMADAS', fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)
    pdf.set_font('helvetica', '', 11)
    solucion_texto = log.informe_tecnico if log.informe_tecnico else "No se registro detalle tecnico."
    pdf.multi_cell(0, 7, limpiar_pdf(solucion_texto))
    
    # --- IMAGEN DE EVIDENCIA ---
    if log.foto_falla:
        pdf.ln(10)
        ruta_foto = os.path.join(app.config['UPLOAD_FOLDER'], log.foto_falla)
        if os.path.exists(ruta_foto):
            pdf.set_font('helvetica', 'B', 12)
            pdf.cell(0, 10, ' 3. EVIDENCIA FOTOGRAFICA', new_x="LMARGIN", new_y="NEXT")
            pdf.image(ruta_foto, x=15, w=100) 
        
    # --- PIE DE PAGINA / FIRMAS ---
    pdf.set_y(-50)
    pdf.set_font('helvetica', 'I', 8)
    pdf.cell(0, 10, 'Este documento es un comprobante oficial de PROESPIA LTDA - Seguridad Electronica.', align='C', new_x="LMARGIN", new_y="NEXT")
    
    pdf.ln(5)
    y_actual = pdf.get_y()
    pdf.line(30, y_actual + 15, 80, y_actual + 15)
    pdf.line(130, y_actual + 15, 180, y_actual + 15)
    pdf.set_font('helvetica', '', 9)
    pdf.text(40, y_actual + 20, "Firma Tecnico")
    pdf.text(140, y_actual + 20, "Recibe Conforme")

    # --- SALIDA FINAL EN BYTES (Solución al AssertionError) ---
    pdf_output = pdf.output()
    
    # Convertimos bytearray a bytes si es necesario y lo metemos en un buffer
    return send_file(
        io.BytesIO(bytes(pdf_output)),
        mimetype='application/pdf',
        as_attachment=False,
        download_name=f"OT_{log.id}.pdf"
    )
# ==========================================
# 9. GESTIÓN DE VISITAS PROGRAMADAS (AGENDA DE TÉCNICOS)
# ==========================================
@app.route('/admin/agenda/<int:user_id>')
@login_required
def ver_agenda(user_id):
    # Ya no necesitamos buscar en session.get, usamos el user_id de la URL
    usuario = Usuario.query.get_or_404(user_id)
    
    visitas = VisitaProgramada.query.filter(VisitaProgramada.falla_id.is_(None)).order_by(VisitaProgramada.fecha_programada.asc()).all()
    clientes = Cliente.query.all()
    tecnicos = Usuario.query.filter_by(rol='tecnico').all()
    
    return render_template('agenda.html', 
                           visitas=visitas, 
                           clientes=clientes, 
                           tecnicos=tecnicos,
                           usuario=usuario,
                           hoy=datetime.now().strftime('%Y-%m-%d'))
    
@app.route('/admin/agendar_visita', methods=['POST'])
@login_required
def agendar_visita():
    # 1. Recogemos los campos del formulario
    fecha_base = request.form.get('fecha_programada_base') 
    hora = request.form.get('hora_visita')                
    
    cliente_id = request.form.get('cliente_id')
    tecnico_id = request.form.get('tecnico_id')
    tipo = request.form.get('tipo_trabajo')
    detalle = request.form.get('descripcion', '')
    ubicacion = request.form.get('ubicacion', '').strip()

    # 2. Validaciones básicas
    if not fecha_base or not hora:
        flash('Error: La fecha y hora son obligatorias', 'danger')
        return redirect(request.referrer)

    # Si es cliente nuevo, no asociar a ningún cliente aún
    if cliente_id == 'nuevo':
        cliente_id = None
    elif not cliente_id:
        flash('Error: Debes seleccionar un cliente', 'danger')
        return redirect(request.referrer)
    else:
        cliente_id = int(cliente_id)

    # 3. Construcción del objeto datetime
    fecha_str = f"{fecha_base} {hora}" 

    try:
        nueva_visita = VisitaProgramada(
            cliente_id=cliente_id,
            usuario_id=int(tecnico_id),
            fecha_programada=datetime.strptime(fecha_str, '%Y-%m-%d %H:%M'),
            tipo_trabajo=tipo,
            descripcion=detalle,
            ubicacion=ubicacion,
            estado='Pendiente' 
        )
        db.session.add(nueva_visita)
        db.session.commit()
        flash('Visita agendada correctamente', 'success')

        db.session.flush()

        # --- DISPARADOR: Nueva visita asignada a técnico ---
        tecnico = Usuario.query.get(int(tecnico_id))
        nom_cliente = 'Cliente Nuevo (Cotización)' if not cliente_id else Cliente.query.get(cliente_id).nombre
        if tecnico:
            notificar_tecnicos(
                'Nueva Visita Asignada',
                f'Visita a {nom_cliente} - {tipo} el {fecha_base}',
                url_for('gestor_visitas', user_id=tecnico_id) if 'gestor_visitas' in dir() else '/',
                tipo='visita'
            )

        db.session.commit()
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error al agendar: {str(e)}', 'danger')

    # ================================================================
    # ARREGLO DEFINITIVO PARA EL BuildError:
    # En lugar de intentar adivinar el ID del admin, simplemente 
    # refrescamos la página donde estábamos (la agenda).
    # ================================================================
    return redirect(request.referrer)

@app.route('/api/eventos_agenda')
def api_eventos_agenda():
    try:
        visitas = VisitaProgramada.query.filter(VisitaProgramada.falla_id.is_(None)).all()
        eventos = []
        
        for v in visitas:
            # Definimos un color según prioridad y origen
            if v.prioridad == 1:
                color = '#dc3545'  # Rojo para críticas
            elif v.falla_id and v.prioridad == 2:
                color = '#fd7e14'  # Naranja para fallas alta
            elif v.falla_id:
                color = '#ffc107'  # Amarillo para fallas normales
            elif 'Cotización' in v.tipo_trabajo:
                color = '#ffc107'  # Amarillo
            elif 'Emergencia' in v.tipo_trabajo:
                color = '#dc3545'  # Rojo
            elif v.estado == 'Vencida':
                color = '#6c757d'  # Gris
            else:
                color = '#8e24aa'  # Morado por defecto

            nom_cliente = v.rel_cliente.nombre if v.rel_cliente else 'SIN CLIENTE'
            nom_tecnico = v.rel_usuario.nombre if v.rel_usuario else 'SIN TÉCNICO'
            eventos.append({
                'id': v.id,
                'title': nom_cliente,
                'start': v.fecha_programada.strftime('%Y-%m-%d'),
                'backgroundColor': color,
                'borderColor': color,
                'extendedProps': {
                    'id': v.id,
                    'tecnico': nom_tecnico,
                    'tipo': v.tipo_trabajo,
                    'estado': v.estado,
                    'descripcion': v.descripcion,
                    'ubicacion': v.ubicacion or '',
                    'fecha': v.fecha_programada.strftime('%Y-%m-%d'),
                    'cliente_id': v.cliente_id,
                    'usuario_id': v.usuario_id,
                    'prioridad': v.prioridad or 3,
                    'falla_id': v.falla_id
                }
            })
        resp = make_response(jsonify(eventos))
        resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        resp.headers['Pragma'] = 'no-cache'
        resp.headers['Expires'] = '0'
        return resp
    except Exception as e:
        print(f"Error en API Agenda: {e}")
        resp = make_response(jsonify([]))
        resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        return resp

@app.route('/api/eventos_por_fecha')
def api_eventos_por_fecha():
    try:
        fecha_str = request.args.get('fecha', '')
        visitas = VisitaProgramada.query.filter(VisitaProgramada.falla_id.is_(None)).all()
        if fecha_str:
            visitas = [v for v in visitas if v.fecha_programada.strftime('%Y-%m-%d') == fecha_str]
        resultados = []
        for v in visitas:
            nom_cliente = v.rel_cliente.nombre if v.rel_cliente else 'SIN CLIENTE'
            nom_tecnico = v.rel_usuario.nombre if v.rel_usuario else 'SIN TÉCNICO'
            resultados.append({
                'id': v.id,
                'title': nom_cliente,
                'hora': v.fecha_programada.strftime('%H:%M'),
                'fecha': v.fecha_programada.strftime('%Y-%m-%d'),
                'fecha_str': v.fecha_programada.strftime('%d/%m/%Y'),
                'tecnico': nom_tecnico,
                'tipo': v.tipo_trabajo,
                'estado': v.estado,
                'descripcion': v.descripcion,
                'ubicacion': v.ubicacion or '',
                'cliente_id': v.cliente_id,
                'usuario_id': v.usuario_id,
                'informe_tecnico': v.informe_tecnico or ''
            })
        resp = make_response(jsonify(resultados))
        resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        return resp
    except Exception as e:
        print(f"Error en API eventos por fecha: {e}")
        resp = make_response(jsonify([]))
        resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        return resp

@app.route('/api/editar_visita/<int:visita_id>', methods=['POST'])
@login_required
def editar_visita(visita_id):
    visita = VisitaProgramada.query.get_or_404(visita_id)
    try:
        data = request.get_json()
        if 'hora' in data:
            fecha_str = data.get('fecha', visita.fecha_programada.strftime('%Y-%m-%d'))
            hora_str = data['hora']
            visita.fecha_programada = datetime.strptime(f'{fecha_str} {hora_str}', '%Y-%m-%d %H:%M')
        if 'tipo_trabajo' in data:
            visita.tipo_trabajo = data['tipo_trabajo']
        if 'descripcion' in data:
            visita.descripcion = data['descripcion']
        if 'tecnico_id' in data:
            visita.usuario_id = int(data['tecnico_id'])
        db.session.commit()
        return jsonify({'ok': True, 'msg': 'Visita actualizada'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'ok': False, 'msg': str(e)}), 400

@app.route('/api/eliminar_visita/<int:visita_id>', methods=['DELETE'])
@login_required
def eliminar_visita(visita_id):
    visita = VisitaProgramada.query.get_or_404(visita_id)
    try:
        db.session.delete(visita)
        db.session.commit()
        return jsonify({'ok': True, 'msg': 'Visita eliminada'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'ok': False, 'msg': str(e)}), 400

@app.route('/api/iniciar_visita/<int:visita_id>', methods=['POST'])
@login_required
def iniciar_visita(visita_id):
    visita = VisitaProgramada.query.get_or_404(visita_id)
    try:
        visita.estado = 'En Curso'
        db.session.commit()
        return jsonify({'ok': True, 'msg': 'Trabajo iniciado'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'ok': False, 'msg': str(e)}), 400

@app.route('/api/completar_visita/<int:visita_id>', methods=['POST'])
@login_required
def completar_visita(visita_id):
    visita = VisitaProgramada.query.get_or_404(visita_id)
    try:
        visita.estado = 'Realizada'
        db.session.commit()
        return jsonify({'ok': True, 'msg': 'Visita completada'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'ok': False, 'msg': str(e)}), 400

# ==========================================
# 11. MÓDULO DE BODEGA Y STOCK TÉCNICO
# ==========================================
@app.route('/inventario/bodega/<int:user_id>')
@app.route('/inventario/bodega/<int:user_id>/<int:page>')
@login_required
def ver_bodega(user_id, page=1):
    usuario = Usuario.query.get_or_404(user_id)

    if usuario.rol == 'tecnico' and usuario.ubicacion_id:
        base_query = ProductoStock.query.filter_by(ubicacion_id=usuario.ubicacion_id)
    else:
        base_query = ProductoStock.query
    pagination = base_query.order_by(ProductoStock.nombre.asc()).paginate(page=page, per_page=20, error_out=False)
    productos = pagination.items

    categorias = CategoriaItem.query.order_by(CategoriaItem.nombre.asc()).all()
    ubicaciones = Ubicacion.query.order_by(Ubicacion.nombre.asc()).all()

    todos_productos_db = ProductoStock.query.order_by(ProductoStock.nombre.asc()).all()
    if usuario.rol == 'tecnico' and usuario.ubicacion_id:
        productos_autocomplete = [p for p in todos_productos_db if p.ubicacion_id == usuario.ubicacion_id]
    else:
        productos_autocomplete = todos_productos_db
    todos_productos = [{
        'id': p.id,
        'nombre': p.nombre,
        'marca': p.marca or '',
        'modelo': p.modelo or '',
        'cantidad': p.cantidad_actual,
        'ubicacion_nombre': p.rel_ubicacion.nombre if p.rel_ubicacion else 'Sin ubicación',
        'categoria_nombre': p.rel_categoria.nombre if p.rel_categoria else ''
    } for p in productos_autocomplete]
    criticos = [p for p in todos_productos_db if p.cantidad_actual < p.cantidad_minima]
    total_bodega = sum(p.cantidad_actual for p in todos_productos_db if p.rel_ubicacion and 'Central' in p.rel_ubicacion.nombre)
    return render_template('inventario_bodega.html',
                           productos=productos,
                           categorias=categorias,
                           ubicaciones=ubicaciones,
                           criticos=criticos,
                           total_bodega=total_bodega,
                           pagination=pagination,
                           todos_productos=todos_productos,
                           usuario=usuario)

@app.route('/api/bodega/crear_producto', methods=['POST'])
@login_required
def crear_producto():
    if current_user.rol not in ['admin', 'super_su']:
        return jsonify({'ok': False, 'msg': 'Permiso denegado'}), 403
    try:
        data = request.get_json()
        nombre = data['nombre']
        marca = data.get('marca', '') or ''
        modelo = data.get('modelo', '') or ''
        cantidad = int(data.get('cantidad', 0))
        cantidad_minima = int(data.get('cantidad_minima', 1))
        valor_estimado = int(data.get('valor', 0))
        estado = data.get('estado', 'Nuevo')
        categoria_id = int(data['categoria_id']) if data.get('categoria_id') else None
        ubicacion_id = int(data['ubicacion_id']) if data.get('ubicacion_id') else None

        existente = ProductoStock.query.filter_by(
            nombre=nombre, marca=marca, modelo=modelo,
            ubicacion_id=ubicacion_id, estado=estado
        ).first()
        if existente:
            existente.cantidad_actual += cantidad
            if cantidad_minima > existente.cantidad_minima:
                existente.cantidad_minima = cantidad_minima
            db.session.commit()
            return jsonify({'ok': True, 'msg': f'Stock actualizado: {existente.cantidad_actual} unidades'})
        else:
            prod = ProductoStock(
                nombre=nombre, marca=marca, modelo=modelo,
                cantidad_actual=cantidad, cantidad_minima=cantidad_minima,
                valor_estimado=valor_estimado, estado=estado,
                categoria_id=categoria_id, ubicacion_id=ubicacion_id
            )
            db.session.add(prod)
            db.session.commit()
            return jsonify({'ok': True, 'msg': 'Producto creado'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'ok': False, 'msg': str(e)}), 400

@app.route('/api/bodega/crear_herramienta', methods=['POST'])
@login_required
def crear_herramienta():
    if current_user.rol not in ['admin', 'super_su']:
        return jsonify({'ok': False, 'msg': 'Permiso denegado'}), 403
    try:
        data = request.get_json()
        nombre = data['nombre']
        cantidad = int(data.get('cantidad', 1))
        ubicacion_id = int(data['ubicacion_id']) if data.get('ubicacion_id') else None

        cat_herramientas = CategoriaItem.query.filter_by(nombre='Herramientas').first()
        if not cat_herramientas:
            cat_herramientas = CategoriaItem(nombre='Herramientas')
            db.session.add(cat_herramientas)
            db.session.flush()

        existente = ProductoStock.query.filter_by(
            nombre=nombre, marca='', modelo='',
            categoria_id=cat_herramientas.id,
            ubicacion_id=ubicacion_id, estado='Nuevo'
        ).first()
        if existente:
            existente.cantidad_actual += cantidad
            db.session.commit()
            return jsonify({'ok': True, 'msg': f'Stock actualizado: {existente.cantidad_actual} unidades'})
        else:
            prod = ProductoStock(
                nombre=nombre, marca='', modelo='',
                cantidad_actual=cantidad, cantidad_minima=1,
                valor_estimado=0, estado='Nuevo',
                categoria_id=cat_herramientas.id, ubicacion_id=ubicacion_id
            )
            db.session.add(prod)
            db.session.commit()
            return jsonify({'ok': True, 'msg': 'Herramienta creada'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'ok': False, 'msg': str(e)}), 400

@app.route('/api/bodega/editar_producto/<int:producto_id>', methods=['POST'])
@login_required
def editar_producto(producto_id):
    if current_user.rol not in ['admin', 'super_su']:
        return jsonify({'ok': False, 'msg': 'Permiso denegado'}), 403
    prod = ProductoStock.query.get_or_404(producto_id)
    try:
        data = request.get_json()
        prod.nombre = data.get('nombre', prod.nombre)
        prod.marca = data.get('marca', prod.marca)
        prod.modelo = data.get('modelo', prod.modelo)
        prod.cantidad_actual = int(data.get('cantidad', prod.cantidad_actual))
        prod.cantidad_minima = int(data.get('cantidad_minima', prod.cantidad_minima))
        prod.valor_estimado = int(data.get('valor', prod.valor_estimado))
        prod.estado = data.get('estado', prod.estado)
        prod.categoria_id = int(data['categoria_id']) if data.get('categoria_id') else None
        prod.ubicacion_id = int(data['ubicacion_id']) if data.get('ubicacion_id') else None
        db.session.commit()
        return jsonify({'ok': True, 'msg': 'Producto actualizado'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'ok': False, 'msg': str(e)}), 400

@app.route('/api/bodega/eliminar_producto/<int:producto_id>', methods=['DELETE'])
@login_required
def eliminar_producto(producto_id):
    if current_user.rol not in ['admin', 'super_su']:
        return jsonify({'ok': False, 'msg': 'Permiso denegado'}), 403
    prod = ProductoStock.query.get_or_404(producto_id)
    try:
        db.session.delete(prod)
        db.session.commit()
        return jsonify({'ok': True, 'msg': 'Producto eliminado'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'ok': False, 'msg': str(e)}), 400

@app.route('/api/bodega/traspaso', methods=['POST'])
@login_required
def traspaso_bodega():
    try:
        data = request.get_json()
        producto_id = int(data['producto_id'])
        desde_id = int(data['desde_id']) if data.get('desde_id') else None
        hacia_id = int(data['hacia_id']) if data.get('hacia_id') else None
        cantidad = int(data['cantidad'])
        descripcion = data.get('descripcion', '')

        if cantidad < 1:
            return jsonify({'ok': False, 'msg': 'Cantidad inválida'}), 400

        if desde_id and hacia_id and desde_id == hacia_id:
            return jsonify({'ok': False, 'msg': 'No puedes transferir a la misma ubicación'}), 400

        prod = ProductoStock.query.get_or_404(producto_id)

        if desde_id:
            if prod.ubicacion_id != desde_id:
                return jsonify({'ok': False, 'msg': 'El producto no está en la ubicación origen'}), 400
            if prod.cantidad_actual < cantidad:
                return jsonify({'ok': False, 'msg': f'Stock insuficiente. Solo hay {prod.cantidad_actual}'}), 400
            prod.cantidad_actual -= cantidad

        if hacia_id:
            destino = ProductoStock.query.filter_by(
                nombre=prod.nombre, marca=prod.marca, modelo=prod.modelo,
                ubicacion_id=hacia_id, estado=prod.estado
            ).first()
            if destino:
                destino.cantidad_actual += cantidad
            else:
                destino = ProductoStock(
                    nombre=prod.nombre, marca=prod.marca, modelo=prod.modelo,
                    cantidad_actual=cantidad, cantidad_minima=prod.cantidad_minima,
                    valor_estimado=prod.valor_estimado, estado=prod.estado,
                    categoria_id=prod.categoria_id, ubicacion_id=hacia_id
                )
                db.session.add(destino)

        mov = MovimientoStock(
            tipo='traspaso', cantidad=cantidad, descripcion=descripcion,
            producto_id=producto_id, desde_ubicacion_id=desde_id,
            hacia_ubicacion_id=hacia_id, usuario_id=current_user.id
        )
        db.session.add(mov)
        db.session.commit()
        return jsonify({'ok': True, 'msg': 'Traspaso realizado'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'ok': False, 'msg': str(e)}), 400

@app.route('/api/bodega/consumo', methods=['POST'])
@login_required
def registrar_consumo():
    try:
        data = request.get_json()
        producto_id = int(data['producto_id'])
        cantidad = int(data['cantidad'])
        descripcion = data.get('descripcion', '')
        ubicacion_id = int(data['ubicacion_id']) if data.get('ubicacion_id') else None

        if cantidad < 1:
            return jsonify({'ok': False, 'msg': 'Cantidad inválida'}), 400

        prod = ProductoStock.query.get_or_404(producto_id)

        if prod.rel_categoria and prod.rel_categoria.nombre == 'Herramientas':
            return jsonify({'ok': False, 'msg': 'No puedes consumir herramientas. Usa Traspaso para moverlas.'}), 400

        if ubicacion_id and prod.ubicacion_id != ubicacion_id:
            return jsonify({'ok': False, 'msg': 'El producto no está en esa ubicación'}), 400
        if prod.cantidad_actual < cantidad:
            return jsonify({'ok': False, 'msg': f'Stock insuficiente. Solo hay {prod.cantidad_actual}'}), 400

        prod.cantidad_actual -= cantidad

        mov = MovimientoStock(
            tipo='consumo', cantidad=cantidad, descripcion=descripcion,
            producto_id=producto_id, desde_ubicacion_id=prod.ubicacion_id,
            usuario_id=current_user.id
        )
        db.session.add(mov)
        db.session.commit()
        
        # --- DISPARADOR: Stock crítico ---
        if prod.cantidad_actual <= prod.cantidad_minima:
            notificar_admin(
                'Stock Crítico en Bodega',
                f'{prod.nombre} ({prod.marca}) bajó a {prod.cantidad_actual} uds. Mínimo: {prod.cantidad_minima}',
                url_for('inventario_bodega', user_id=1) if 'inventario_bodega' in dir() else '/',
                tipo='stock',
                exclude_id=current_user.id
            )
        return jsonify({'ok': True, 'msg': 'Consumo registrado'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'ok': False, 'msg': str(e)}), 400

# ==========================================
# 10. GESTIÓN DE VEHÍCULOS
# ==========================================

@app.route('/inventario/vehiculos')
@login_required
def listar_vehiculos():
    vehiculos = Vehiculo.query.order_by(Vehiculo.created_at.desc()).all()
    ubicaciones = Ubicacion.query.order_by(Ubicacion.nombre).all()
    tecnicos = Usuario.query.filter_by(rol='tecnico').all()
    return render_template('gestion_vehiculos.html', vehiculos=vehiculos, ubicaciones=ubicaciones, tecnicos=tecnicos, usuario=current_user)

@app.route('/api/vehiculos/crear', methods=['POST'])
@login_required
def crear_vehiculo():
    if current_user.rol not in ['admin', 'super_su']:
        return jsonify({'ok': False, 'msg': 'No autorizado'}), 403
    try:
        data = request.get_json()
        placa = data['placa'].strip().upper()
        modelo = data.get('modelo', '').strip()
        dia_checklist = data.get('dia_checklist', 4)
        nombre = f'Camioneta {placa}'
        ubicacion = Ubicacion(nombre=nombre, color='warning')
        db.session.add(ubicacion)
        db.session.flush()
        v = Vehiculo(placa=placa, modelo=modelo, dia_checklist=dia_checklist, ubicacion_id=ubicacion.id)
        db.session.add(v)
        db.session.commit()
        return jsonify({'ok': True, 'msg': 'Vehículo creado'})
    except IntegrityError:
        db.session.rollback()
        return jsonify({'ok': False, 'msg': 'Ya existe un vehículo con esa placa'}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'ok': False, 'msg': str(e)}), 400

@app.route('/api/vehiculos/editar/<int:id>', methods=['POST'])
@login_required
def editar_vehiculo(id):
    if current_user.rol not in ['admin', 'super_su']:
        return jsonify({'ok': False, 'msg': 'No autorizado'}), 403
    try:
        v = Vehiculo.query.get_or_404(id)
        data = request.get_json()
        placa = data['placa'].strip().upper()
        modelo = data.get('modelo', '').strip()
        dia_checklist = data.get('dia_checklist', 4)
        v.placa = placa
        v.modelo = modelo
        v.dia_checklist = dia_checklist
        if v.rel_ubicacion:
            v.rel_ubicacion.nombre = f'Camioneta {placa}'
        db.session.commit()
        return jsonify({'ok': True, 'msg': 'Vehículo actualizado'})
    except IntegrityError:
        db.session.rollback()
        return jsonify({'ok': False, 'msg': 'Ya existe un vehículo con esa placa'}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'ok': False, 'msg': str(e)}), 400

@app.route('/api/vehiculos/eliminar/<int:id>', methods=['DELETE'])
@login_required
def eliminar_vehiculo(id):
    if current_user.rol not in ['admin', 'super_su']:
        return jsonify({'ok': False, 'msg': 'No autorizado'}), 403
    try:
        v = Vehiculo.query.get_or_404(id)
        tecnicos_asignados = Usuario.query.filter_by(ubicacion_id=v.ubicacion_id).count()
        if tecnicos_asignados > 0:
            return jsonify({'ok': False, 'msg': f'No se puede eliminar: {tecnicos_asignados} técnico(s) asignado(s) a este vehículo'}), 400
        if v.rel_ubicacion:
            prod_count = ProductoStock.query.filter_by(ubicacion_id=v.ubicacion_id).count()
            if prod_count > 0:
                return jsonify({'ok': False, 'msg': f'No se puede eliminar: hay {prod_count} producto(s) en este vehículo'}), 400
            db.session.delete(v.rel_ubicacion)
        db.session.delete(v)
        db.session.commit()
        return jsonify({'ok': True, 'msg': 'Vehículo eliminado'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'ok': False, 'msg': str(e)}), 400

@app.route('/api/vehiculos/asignar', methods=['POST'])
@login_required
def asignar_vehiculo():
    if current_user.rol not in ['admin', 'super_su']:
        return jsonify({'ok': False, 'msg': 'No autorizado'}), 403
    try:
        data = request.get_json()
        usuario_id = int(data['usuario_id'])
        vehiculo_id = int(data.get('vehiculo_id', 0))
        tipo = data.get('tipo_asignacion', 'acompanante')
        user = Usuario.query.get_or_404(usuario_id)
        if vehiculo_id:
            v = Vehiculo.query.get_or_404(vehiculo_id)
            user.ubicacion_id = v.ubicacion_id
            user.tipo_asignacion = tipo
        else:
            user.ubicacion_id = None
            user.tipo_asignacion = 'acompanante'
        db.session.commit()
        return jsonify({'ok': True, 'msg': 'Asignación actualizada'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'ok': False, 'msg': str(e)}), 400

# ==========================================
# SOLICITUD DE COMBUSTIBLE (Técnico)
# ==========================================
@app.route('/vehiculo/solicitar_combustible', methods=['POST'])
@login_required
def solicitar_combustible():
    if current_user.rol != 'tecnico':
        return jsonify({'ok': False, 'msg': 'Solo técnicos pueden solicitar combustible'}), 403
    try:
        vehiculo = Vehiculo.query.filter(Vehiculo.ubicacion_id == current_user.ubicacion_id).first()
        if not vehiculo:
            return jsonify({'ok': False, 'msg': 'No tienes un vehículo asignado'}), 400
        monto = int(request.form.get('monto', 0))
        km = int(request.form.get('kilometraje', 0))
        if monto < 1000:
            return jsonify({'ok': False, 'msg': 'Monto mínimo: $1.000'}), 400

        solicitud = SolicitudCombustible(
            usuario_id=current_user.id,
            vehiculo_id=vehiculo.id,
            monto=monto,
            kilometraje=km
        )
        db.session.add(solicitud)
        db.session.commit()

        notificar_admin(
            'Solicitud de Combustible',
            f'{current_user.nombre} solicita ${monto:,} para {vehiculo.placa}. KM actual: {km:,}',
            url_for('dashboard', user_id=1),
            tipo='combustible'
        )
        return jsonify({'ok': True, 'msg': 'Solicitud enviada al administrador'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'ok': False, 'msg': str(e)}), 400

# ==========================================
# MARCAR SOLICITUD COMBUSTIBLE ATENDIDA
# ==========================================
@app.route('/api/combustible/atender/<int:solicitud_id>', methods=['POST'])
@login_required
def atender_combustible(solicitud_id):
    if current_user.rol not in ['admin', 'super_su']:
        return jsonify({'ok': False, 'msg': 'No autorizado'}), 403
    sol = SolicitudCombustible.query.get_or_404(solicitud_id)
    sol.estado = 'Atendido'
    db.session.commit()
    return jsonify({'ok': True})

# ==========================================
# 11. CHECKLIST SEMANAL DE HERRAMIENTAS
# ==========================================

DIAS_SEMANA = ['Lunes','Martes','Miércoles','Jueves','Viernes','Sábado','Domingo']

@app.route('/checklist/viernes')
@login_required
def checklist_viernes():
    if current_user.rol != 'tecnico':
        flash('Solo técnicos pueden acceder al checklist.', 'warning')
        return redirect(url_for('dashboard', user_id=current_user.id))
    vehiculo = Vehiculo.query.filter(Vehiculo.ubicacion_id == current_user.ubicacion_id).first()
    if not vehiculo:
        flash('No tienes un vehículo asignado. Contacta al administrador.', 'danger')
        return redirect(url_for('dashboard', user_id=current_user.id))
    hoy = datetime.now().weekday()
    dia_config = vehiculo.dia_checklist
    dia_habilitado = (hoy == dia_config)
    hoy_chile = date.today()
    ya_completado_hoy = ChecklistSemanal.query.filter(
        ChecklistSemanal.vehiculo_id == vehiculo.id,
        db.func.date(ChecklistSemanal.fecha_registro) == hoy_chile.isoformat()
    ).first() is not None
    herramientas = ProductoStock.query.join(CategoriaItem).filter(
        CategoriaItem.nombre == 'Herramientas',
        ProductoStock.ubicacion_id == vehiculo.ubicacion_id
    ).order_by(ProductoStock.nombre).all()
    if not herramientas:
        flash('Tu vehículo no tiene herramientas registradas. Contacta al administrador.', 'warning')
    return render_template('checklist_viernes.html', usuario=current_user, vehiculo=vehiculo, herramientas=herramientas, dia_habilitado=dia_habilitado, dia_nombre=DIAS_SEMANA[dia_config], ya_completado_hoy=ya_completado_hoy)

@app.route('/checklist/enviar', methods=['POST'])
@login_required
def checklist_enviar():
    if current_user.rol != 'tecnico':
        return jsonify({'ok': False, 'msg': 'No autorizado'}), 403
    try:
        vehiculo = Vehiculo.query.filter(Vehiculo.ubicacion_id == current_user.ubicacion_id).first()
        if not vehiculo:
            return jsonify({'ok': False, 'msg': 'Sin vehículo asignado'}), 400
        hoy = datetime.now().weekday()
        if hoy != vehiculo.dia_checklist:
            return jsonify({'ok': False, 'msg': 'Hoy no es día de checklist para tu vehículo'}), 400
        hoy_chile = date.today()
        ya_hoy = ChecklistSemanal.query.filter(
            ChecklistSemanal.vehiculo_id == vehiculo.id,
            db.func.date(ChecklistSemanal.fecha_registro) == hoy_chile.isoformat()
        ).first()
        if ya_hoy:
            return jsonify({'ok': False, 'msg': 'El checklist ya fue completado hoy'}), 400
        herramientas_ok = request.form.getlist('herramientas_ok')
        obs = request.form.get('observaciones', '').strip()
        total = ProductoStock.query.join(CategoriaItem).filter(
            CategoriaItem.nombre == 'Herramientas',
            ProductoStock.ubicacion_id == vehiculo.ubicacion_id
        ).count()
        ok_count = len(herramientas_ok)
        estado = (ok_count == total)
        ck = ChecklistSemanal(
            usuario_id=current_user.id,
            vehiculo_id=vehiculo.id,
            estado_completo=estado,
            observaciones=obs,
            herramientas_ok=','.join(herramientas_ok)
        )
        db.session.add(ck)
        db.session.commit()
        return jsonify({'ok': True, 'checklist_id': ck.id, 'msg': 'Checklist guardado'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'ok': False, 'msg': str(e)}), 400

@app.route('/checklist/vehiculo/<int:vehiculo_id>', methods=['GET', 'POST'])
@login_required
def checklist_vehiculo_admin(vehiculo_id):
    if current_user.rol not in ['admin', 'super_su']:
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard', user_id=current_user.id))
    vehiculo = Vehiculo.query.get_or_404(vehiculo_id)
    if request.method == 'POST':
        try:
            herramientas_ok = request.form.getlist('herramientas_ok')
            obs = request.form.get('observaciones', '').strip()
            total = ProductoStock.query.join(CategoriaItem).filter(
                CategoriaItem.nombre == 'Herramientas',
                ProductoStock.ubicacion_id == vehiculo.ubicacion_id
            ).count()
            ok_count = len(herramientas_ok)
            estado = (ok_count == total)
            tecnico_asignado = Usuario.query.filter_by(ubicacion_id=vehiculo.ubicacion_id, rol='tecnico', tipo_asignacion='a_cargo').first()
            if not tecnico_asignado:
                tecnico_asignado = Usuario.query.filter_by(ubicacion_id=vehiculo.ubicacion_id, rol='tecnico').first()
            ck = ChecklistSemanal(
                usuario_id=tecnico_asignado.id if tecnico_asignado else current_user.id,
                vehiculo_id=vehiculo.id,
                estado_completo=estado,
                observaciones=obs,
                herramientas_ok=','.join(herramientas_ok)
            )
            db.session.add(ck)
            db.session.commit()
            flash(f'Checklist guardado. <a href="/checklist/reporte_pdf/{ck.id}" target="_blank" class="alert-link"><i class="fa-solid fa-file-pdf me-1"></i>Descargar PDF</a>', 'success')
            return redirect(url_for('listar_vehiculos'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al guardar: {e}', 'danger')
            return redirect(url_for('checklist_vehiculo_admin', vehiculo_id=vehiculo.id))
    herramientas = ProductoStock.query.join(CategoriaItem).filter(
        CategoriaItem.nombre == 'Herramientas',
        ProductoStock.ubicacion_id == vehiculo.ubicacion_id
    ).order_by(ProductoStock.nombre).all()
    hoy_chile = date.today()
    ya_completado_hoy = ChecklistSemanal.query.filter(
        ChecklistSemanal.vehiculo_id == vehiculo.id,
        db.func.date(ChecklistSemanal.fecha_registro) == hoy_chile.isoformat()
    ).first() is not None
    return render_template('checklist_viernes.html', usuario=current_user, vehiculo=vehiculo, herramientas=herramientas, dia_habilitado=True, dia_nombre='Hoy', ya_completado_hoy=ya_completado_hoy)

@app.route('/checklist/reporte_pdf/<int:checklist_id>')
@login_required
def checklist_reporte_pdf(checklist_id):
    ck = ChecklistSemanal.query.get_or_404(checklist_id)
    if current_user.rol not in ['admin', 'super_su'] and ck.usuario_id != current_user.id:
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard', user_id=current_user.id))
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font('helvetica', 'B', 20)
    pdf.set_text_color(220, 53, 69)
    pdf.cell(0, 12, 'PROESPIA LTDA', align='L', new_x="LMARGIN", new_y="NEXT")
    pdf.set_font('helvetica', '', 8)
    pdf.set_text_color(120, 120, 120)
    pdf.cell(0, 5, 'Acta de Entrega de Herramientas - Checklist Semanal', new_x="LMARGIN", new_y="NEXT")
    pdf.ln(8)
    pdf.set_text_color(0, 0, 0)
    pdf.set_font('helvetica', 'B', 10)
    pdf.cell(40, 6, 'Tecnico:')
    pdf.set_font('helvetica', '', 10)
    pdf.cell(60, 6, ck.rel_usuario.nombre, new_x="LMARGIN", new_y="NEXT")
    pdf.set_font('helvetica', 'B', 10)
    pdf.cell(40, 6, 'Vehiculo:')
    pdf.set_font('helvetica', '', 10)
    pdf.cell(60, 6, ck.rel_vehiculo.placa + ' - ' + (ck.rel_vehiculo.modelo or ''), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font('helvetica', 'B', 10)
    pdf.cell(40, 6, 'Fecha:')
    pdf.set_font('helvetica', '', 10)
    pdf.cell(60, 6, ck.fecha_registro.strftime('%d/%m/%Y %H:%M'), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)
    vehiculo = Vehiculo.query.get(ck.vehiculo_id)
    herramientas = ProductoStock.query.join(CategoriaItem).filter(
        CategoriaItem.nombre == 'Herramientas',
        ProductoStock.ubicacion_id == vehiculo.ubicacion_id
    ).order_by(ProductoStock.nombre).all()
    herramientas_ok = (ck.herramientas_ok or '').split(',')
    pdf.set_font('helvetica', 'B', 9)
    pdf.set_fill_color(30, 30, 30)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(10, 7, '#', 1, 0, 'C', True)
    pdf.cell(120, 7, 'HERRAMIENTA', 1, 0, 'C', True)
    pdf.cell(60, 7, 'ESTADO', 1, 1, 'C', True)
    pdf.set_text_color(0, 0, 0)
    pdf.set_font('helvetica', '', 9)
    for i, h in enumerate(herramientas, 1):
        ok = h.nombre in herramientas_ok
        pdf.cell(10, 6, str(i), 1, 0, 'C')
        pdf.cell(120, 6, h.nombre, 1)
        pdf.set_font('helvetica', 'B', 9)
        if ok:
            pdf.set_text_color(40, 167, 69)
            pdf.cell(60, 6, 'OK', 1, 1, 'C')
        else:
            pdf.set_text_color(220, 53, 69)
            pdf.cell(60, 6, 'FALTANTE', 1, 1, 'C')
        pdf.set_text_color(0, 0, 0)
        pdf.set_font('helvetica', '', 8)
    pdf.ln(10)
    if ck.observaciones:
        pdf.set_font('helvetica', 'B', 9)
        pdf.cell(0, 5, 'Observaciones:', new_x="LMARGIN", new_y="NEXT")
        pdf.set_font('helvetica', '', 9)
        pdf.multi_cell(0, 5, ck.observaciones)
        pdf.ln(5)
    linea_firma = pdf.get_y()
    if linea_firma < 230:
        linea_firma = 230
    pdf.set_y(linea_firma)
    pdf.set_draw_color(100, 100, 100)
    pdf.line(20, linea_firma, 100, linea_firma)
    pdf.set_font('helvetica', '', 8)
    pdf.set_text_color(120, 120, 120)
    pdf.cell(0, 4, 'Firma Digital de Conformidad', new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 4, ck.rel_usuario.nombre + ' - ' + ck.fecha_registro.strftime('%d/%m/%Y %H:%M'), new_x="LMARGIN", new_y="NEXT")
    pdf_output = pdf.output()
    return send_file(
        io.BytesIO(bytes(pdf_output)),
        mimetype='application/pdf',
        as_attachment=False,
        download_name=f'checklist_{checklist_id}.pdf'
    )

@app.route('/api/checklist/historial/<int:vehiculo_id>')
@login_required
def checklist_historial(vehiculo_id):
    if current_user.rol not in ['admin', 'super_su']:
        return jsonify({'ok': False, 'msg': 'No autorizado'}), 403
    checks = ChecklistSemanal.query.filter_by(vehiculo_id=vehiculo_id).order_by(ChecklistSemanal.fecha_registro.desc()).all()
    data = [{
        'id': c.id,
        'fecha': c.fecha_registro.strftime('%d/%m/%Y %H:%M'),
        'tecnico': c.rel_usuario.nombre,
        'estado': 'Completo' if c.estado_completo else 'Faltantes',
        'estado_badge': 'success' if c.estado_completo else 'danger',
        'observaciones': c.observaciones or ''
    } for c in checks]
    return jsonify({'ok': True, 'checks': data})

# ==========================================
# 11b. GESTIÓN DE HERRAMIENTAS POR VEHÍCULO
# ==========================================

@app.route('/api/vehiculos/<int:vehiculo_id>/herramientas', methods=['GET', 'POST'])
@login_required
def herramientas_vehiculo(vehiculo_id):
    v = Vehiculo.query.get_or_404(vehiculo_id)
    if request.method == 'GET':
        herramientas = Herramienta.query.filter_by(vehiculo_id=vehiculo_id).order_by(Herramienta.nombre).all()
        return jsonify({'ok': True, 'herramientas': [{'id': h.id, 'nombre': h.nombre, 'codigo': h.codigo_inventario} for h in herramientas], 'total': len(herramientas)})
    if current_user.rol not in ['admin', 'super_su']:
        return jsonify({'ok': False, 'msg': 'No autorizado'}), 403
    try:
        data = request.get_json()
        nombre = data['nombre'].strip()
        slug = nombre.lower().replace(' ', '_')[:20]
        codigo_vehiculo = f'{slug}-{vehiculo_id}'
        h = Herramienta(nombre=nombre, codigo_inventario=codigo_vehiculo, vehiculo_id=vehiculo_id)
        db.session.add(h)
        db.session.commit()
        return jsonify({'ok': True, 'msg': 'Herramienta agregada'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'ok': False, 'msg': str(e)}), 400

@app.route('/api/herramientas/eliminar/<int:herramienta_id>', methods=['DELETE'])
@login_required
def eliminar_herramienta(herramienta_id):
    if current_user.rol not in ['admin', 'super_su']:
        return jsonify({'ok': False, 'msg': 'No autorizado'}), 403
    try:
        h = Herramienta.query.get_or_404(herramienta_id)
        db.session.delete(h)
        db.session.commit()
        return jsonify({'ok': True, 'msg': 'Herramienta eliminada'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'ok': False, 'msg': str(e)}), 400

# ==========================================
# 11b. WEB PUSH NOTIFICATIONS & HELPERS
# ==========================================
def crear_notificacion(usuario_id, titulo, mensaje, url=None, tipo='info', enviar_push=True):
    """Crea una notificación in-app y opcionalmente envía push."""
    notif = Notificacion(
        usuario_id=usuario_id,
        titulo=titulo,
        mensaje=mensaje,
        url=url,
        tipo=tipo
    )
    db.session.add(notif)
    db.session.commit()
    print(f"[NOTIF] Creada: user={usuario_id} tipo={tipo} titulo={titulo[:50]}")

    if enviar_push:
        subs = PushSubscription.query.filter_by(usuario_id=usuario_id).all()
        print(f"[NOTIF] Push subscriptions encontradas: {len(subs)}")
        for s in subs:
            try:
                from pywebpush import webpush
                import requests
                data = json.dumps({
                    'titulo': titulo,
                    'cuerpo': mensaje,
                    'url': url or '/',
                    'icon': '/static/icons/icon-192x192.png'
                })
                resp = webpush(
                    subscription_info={'endpoint': s.endpoint, 'keys': {'auth': s.auth, 'p256dh': s.p256dh}},
                    data=data,
                    vapid_private_key=app.config['VAPID_PRIVATE_KEY'],
                    vapid_claims={'sub': app.config['VAPID_CLAIM_EMAIL']},
                    ttl=86400,
                    timeout=5,
                    headers={'Urgency': 'high'}
                )
                print(f"[NOTIF] Push enviado OK: {s.endpoint[:30]}... status={resp.status_code}")
            except requests.Timeout:
                print(f"[NOTIF] Push TIMEOUT: {s.endpoint[:30]}... pasando a la siguiente")
            except Exception as e:
                err_str = str(e)
                print(f"[NOTIF] Push FALLÓ: {s.endpoint[:30]}... error={err_str[:200]}")
                if '410' in err_str or 'gone' in err_str.lower():
                    print(f"[NOTIF] Suscripción expirada (410), eliminando")
                    db.session.delete(s)
                    db.session.commit()
    return notif

def notificar_admin(titulo, mensaje, url=None, tipo='info', exclude_id=None):
    """Envía notificación a todos los admins y super_su."""
    admins = Usuario.query.filter(Usuario.rol.in_(['admin', 'super_su'])).all()
    for a in admins:
        if exclude_id and a.id == exclude_id:
            continue
        crear_notificacion(a.id, titulo, mensaje, url, tipo)

def notificar_tecnicos(titulo, mensaje, url=None, tipo='info', exclude_id=None):
    """Envía notificación a todos los técnicos."""
    tecnicos = Usuario.query.filter_by(rol='tecnico').all()
    for t in tecnicos:
        if exclude_id and t.id == exclude_id:
            continue
        crear_notificacion(t.id, titulo, mensaje, url, tipo)

def notificar_operadores(titulo, mensaje, url=None, tipo='info', exclude_id=None):
    """Envía notificación a todos los operadores."""
    ops = Usuario.query.filter_by(rol='operador').all()
    for o in ops:
        if exclude_id and o.id == exclude_id:
            continue
        crear_notificacion(o.id, titulo, mensaje, url, tipo)

@app.route('/api/push/subscribe', methods=['POST'])
@login_required
def push_subscribe():
    datos = request.get_json()
    if not datos or not datos.get('endpoint'):
        return jsonify({'ok': False, 'msg': 'Faltan datos'}), 400

    existing = PushSubscription.query.filter_by(endpoint=datos['endpoint']).first()
    if existing:
        if existing.usuario_id != current_user.id:
            existing.usuario_id = current_user.id
            existing.auth = datos['keys']['auth']
            existing.p256dh = datos['keys']['p256dh']
            db.session.commit()
        return jsonify({'ok': True, 'msg': 'Ya suscrito'})

    sub = PushSubscription(
        endpoint=datos['endpoint'],
        auth=datos['keys']['auth'],
        p256dh=datos['keys']['p256dh'],
        usuario_id=current_user.id
    )
    db.session.add(sub)
    db.session.commit()

    # Enviar notificación de bienvenida
    crear_notificacion(current_user.id, 'Notificaciones activadas',
        'Recibirás alertas del sistema Proespia aquí.', tipo='exito')
    return jsonify({'ok': True, 'msg': 'Suscrito exitosamente'})

@app.route('/api/push/unsubscribe', methods=['POST'])
@login_required
def push_unsubscribe():
    datos = request.get_json()
    if not datos or not datos.get('endpoint'):
        return jsonify({'ok': False, 'msg': 'Faltan datos'}), 400

    PushSubscription.query.filter_by(
        endpoint=datos['endpoint'],
        usuario_id=current_user.id
    ).delete()
    db.session.commit()
    return jsonify({'ok': True, 'msg': 'Suscripción eliminada'})

@app.route('/api/push/test', methods=['POST'])
@login_required
def push_test():
    """Envía un push de prueba al usuario actual. Solo admin/super_su."""
    if current_user.rol not in ['admin', 'super_su']:
        return jsonify({'ok': False, 'msg': 'No autorizado'}), 403

    subs = PushSubscription.query.filter_by(usuario_id=current_user.id).all()
    if not subs:
        return jsonify({'ok': False, 'msg': 'No tienes suscripciones push. Activa las notificaciones primero.'})

    try:
        from pywebpush import webpush
        import requests
        results = []
        for s in subs:
            try:
                data = json.dumps({
                    'titulo': 'Test de notificación',
                    'cuerpo': 'Si ves esto, las notificaciones push funcionan correctamente.',
                    'url': '/dashboard/' + str(current_user.id),
                    'icon': '/static/icons/icon-192x192.png'
                })
                resp = webpush(
                    subscription_info={'endpoint': s.endpoint, 'keys': {'auth': s.auth, 'p256dh': s.p256dh}},
                    data=data,
                    vapid_private_key=app.config['VAPID_PRIVATE_KEY'],
                    vapid_claims={'sub': app.config['VAPID_CLAIM_EMAIL']},
                    ttl=86400,
                    timeout=5,
                    headers={'Urgency': 'high'}
                )
                results.append({'endpoint': s.endpoint[:30], 'status': resp.status_code, 'ok': True})
            except requests.Timeout:
                results.append({'endpoint': s.endpoint[:30], 'error': 'Timeout (5s)', 'ok': False})
            except Exception as e:
                results.append({'endpoint': s.endpoint[:30], 'error': str(e)[:150], 'ok': False})
                if '410' in str(e):
                    db.session.delete(s)
                    db.session.commit()
        return jsonify({'ok': True, 'results': results})
    except Exception as e:
        return jsonify({'ok': False, 'msg': str(e)}), 500

@app.route('/api/notificaciones')
@login_required
def listar_notificaciones():
    pagina = request.args.get('pagina', 1, type=int)
    q = Notificacion.query.filter_by(usuario_id=current_user.id).order_by(Notificacion.created_at.desc())
    no_leidas = q.filter_by(leida=False).count()
    notifs = q.paginate(page=pagina, per_page=10, error_out=False)
    resp = jsonify({
        'ok': True,
        'no_leidas': no_leidas,
        'total': q.count(),
        'items': [{
            'id': n.id,
            'titulo': n.titulo,
            'mensaje': n.mensaje,
            'url': n.url,
            'leida': n.leida,
            'tipo': n.tipo,
            'created_at': n.created_at.strftime('%d/%m %H:%M')
        } for n in notifs.items]
    })
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    return resp

@app.route('/api/notificaciones/marcar-leida', methods=['POST'])
@login_required
def marcar_notificacion_leida():
    datos = request.get_json()
    notif_id = datos.get('id')
    if notif_id == 'todas':
        Notificacion.query.filter_by(usuario_id=current_user.id, leida=False).update({'leida': True})
    else:
        n = Notificacion.query.get_or_404(notif_id)
        if n.usuario_id != current_user.id:
            return jsonify({'ok': False, 'msg': 'No autorizado'}), 403
        n.leida = True
    db.session.commit()
    return jsonify({'ok': True})

@app.route('/api/notificaciones/eliminar', methods=['POST'])
@login_required
def eliminar_notificacion():
    datos = request.get_json()
    if datos.get('id') == 'todas':
        Notificacion.query.filter_by(usuario_id=current_user.id).delete()
    else:
        n = Notificacion.query.get_or_404(datos.get('id'))
        if n.usuario_id != current_user.id:
            return jsonify({'ok': False, 'msg': 'No autorizado'}), 403
        db.session.delete(n)
    db.session.commit()
    return jsonify({'ok': True})

# ==========================================
# 12. EJECUCIÓN DE LA APLICACIÓN
# ==========================================
with app.app_context():
    db.create_all()
    # Migrar columna password a 255 chars si es necesario
    try:
        db.session.execute(db.text('ALTER TABLE usuario ALTER COLUMN password TYPE VARCHAR(255)'))
        db.session.commit()
    except Exception:
        db.session.rollback()
    # Migrar columna contacto_emergencia en cliente si no existe
    try:
        db.session.execute(db.text('ALTER TABLE cliente ADD COLUMN contacto_emergencia VARCHAR(500)'))
        db.session.commit()
    except Exception:
        db.session.rollback()
    # Migrar tamaño contacto_emergencia a 500 si ya existe
    try:
        db.session.execute(db.text('ALTER TABLE cliente ALTER COLUMN contacto_emergencia TYPE VARCHAR(500)'))
        db.session.commit()
    except Exception:
        db.session.rollback()
    # Migrar visita_programada.cliente_id a nullable
    try:
        db.session.execute(db.text('ALTER TABLE visita_programada ALTER COLUMN cliente_id DROP NOT NULL'))
        db.session.commit()
    except Exception:
        db.session.rollback()
    # Migrar columnas nuevas de visita_programada
    for col in ['informe_tecnico', 'foto_visita']:
        try:
            db.session.execute(db.text(f'ALTER TABLE visita_programada ADD COLUMN {col} TEXT'))
            db.session.commit()
        except Exception:
            db.session.rollback()
    try:
        db.session.execute(db.text('ALTER TABLE visita_programada ADD COLUMN fecha_completada TIMESTAMP'))
        db.session.commit()
    except Exception:
        db.session.rollback()
    try:
        db.session.execute(db.text('ALTER TABLE visita_programada ALTER COLUMN fecha_completada TYPE TIMESTAMP USING fecha_completada::timestamp'))
        db.session.commit()
    except Exception:
        db.session.rollback()
    # Migrar falla_id en visita_programada (unificación Fallas + Agenda)
    try:
        db.session.execute(db.text('ALTER TABLE visita_programada ADD COLUMN falla_id INTEGER'))
        db.session.commit()
    except Exception:
        db.session.rollback()
    # Migrar prioridad en visita_programada
    try:
        db.session.execute(db.text('ALTER TABLE visita_programada ADD COLUMN prioridad INTEGER DEFAULT 3'))
        db.session.commit()
    except Exception:
        db.session.rollback()
    # Backfill: crear VisitaProgramada para fallas existentes de Bitácora
    try:
        fallas_existentes = Bitacora.query.filter(
            Bitacora.tipo_visita.ilike('%Falla%'),
            ~Bitacora.tipo_visita.ilike('%RESUELTA%')
        ).all()
        for fb in fallas_existentes:
            existente = VisitaProgramada.query.filter_by(falla_id=fb.id).first()
            if existente:
                if existente.estado == 'Vencida':
                    existente.estado = 'Pendiente'
                    existente.fecha_programada = datetime.now()
            else:
                visita = VisitaProgramada(
                    cliente_id=fb.cliente_id,
                    usuario_id=fb.usuario_id or 1,
                    tipo_trabajo='Reparación',
                    descripcion=f"[Falla desde Bitácora] {fb.descripcion}",
                    estado='Pendiente',
                    prioridad=fb.prioridad or 3,
                    falla_id=fb.id,
                    fecha_programada=datetime.now()
                )
                db.session.add(visita)
        db.session.commit()
        cnt = fallas_existentes.count if hasattr(fallas_existentes, 'count') else len(fallas_existentes)
        print(f"Backfill: {cnt} fallas de Bitácora procesadas")
    except Exception as e:
        db.session.rollback()
        print(f"Backfill error: {e}")
    # ==========================================
    # 12.1 ARQUITECTURA DE AUTENTICACIÓN — MIGRACIONES + SÚPER ADMIN
    # ==========================================
    # Migración: nuevas columnas en usuario (correo, google_id, token_recuperacion, estado, created_at)
    for col_sql, _ in [
        ("ALTER TABLE usuario ADD COLUMN correo VARCHAR(120)", None),
        ("CREATE UNIQUE INDEX IF NOT EXISTS ix_usuario_correo ON usuario(correo)", None),
        ("ALTER TABLE usuario ADD COLUMN google_id VARCHAR(120)", None),
        ("CREATE UNIQUE INDEX IF NOT EXISTS ix_usuario_google_id ON usuario(google_id)", None),
        ("ALTER TABLE usuario ADD COLUMN token_recuperacion VARCHAR(200)", None),
        ("ALTER TABLE usuario ADD COLUMN estado VARCHAR(20)", None),
        ("ALTER TABLE usuario ADD COLUMN created_at TIMESTAMP", None),
    ]:
        try:
            db.session.execute(db.text(col_sql))
            db.session.commit()
        except Exception:
            db.session.rollback()
    # SQLite: DROP NOT NULL no soportado vía ALTER. Recreamos via COPY solo si hace falta.
    try:
        cols_info = db.session.execute(db.text("PRAGMA table_info(usuario)")).fetchall()
        # cols_info: (cid, name, type, notnull, dflt_value, pk)
        info = {c[1]: c for c in cols_info}
        needs_rebuild = (
            ('username' in info and info['username'][3] == 1) or
            ('password' in info and info['password'][3] == 1)
        )
        if needs_rebuild:
            db.session.execute(db.text("ALTER TABLE usuario RENAME TO _usuario_old"))
            db.session.execute(db.text("""
                CREATE TABLE usuario (
                    id INTEGER PRIMARY KEY,
                    nombre VARCHAR(100) NOT NULL,
                    username VARCHAR(50),
                    password VARCHAR(255),
                    rol VARCHAR(20) DEFAULT 'Pendiente',
                    ubicacion_id INTEGER,
                    tipo_asignacion VARCHAR(20) DEFAULT 'acompanante',
                    correo VARCHAR(120),
                    google_id VARCHAR(120),
                    token_recuperacion VARCHAR(200),
                    estado VARCHAR(20) DEFAULT 'Activo',
                    created_at TIMESTAMP
                )
            """))
            db.session.execute(db.text("""
                INSERT INTO usuario (id, nombre, username, password, rol, ubicacion_id, tipo_asignacion,
                                     correo, google_id, token_recuperacion, estado, created_at)
                SELECT id, nombre, username, password, rol, ubicacion_id, tipo_asignacion,
                       correo, google_id, token_recuperacion, estado, created_at
                FROM _usuario_old
            """))
            db.session.execute(db.text("DROP TABLE _usuario_old"))
            db.session.execute(db.text("CREATE UNIQUE INDEX IF NOT EXISTS ix_usuario_correo ON usuario(correo)"))
            db.session.execute(db.text("CREATE UNIQUE INDEX IF NOT EXISTS ix_usuario_google_id ON usuario(google_id)"))
            db.session.commit()
            print('Migración: tabla usuario reconstruida (password y username ahora NULLable).')
        else:
            db.session.rollback()
    except Exception as e:
        db.session.rollback()
        print(f'Migración rebuild usuario: {e}')

    # Backfill: poblar `correo` desde `username` para usuarios legacy
    try:
        db.session.execute(db.text(
            "UPDATE usuario SET correo = LOWER(username) || '@proespia.local' WHERE correo IS NULL OR correo = ''"
        ))
        db.session.commit()
    except Exception:
        db.session.rollback()
    # Backfill: asignar estado 'Activo' y created_at a usuarios legacy
    try:
        db.session.execute(db.text(
            "UPDATE usuario SET estado = 'Activo' WHERE estado IS NULL OR estado = ''"
        ))
        db.session.execute(db.text(
            "UPDATE usuario SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL"
        ))
        db.session.commit()
    except Exception:
        db.session.rollback()

    # Súper Admin obligatorio: si la tabla está vacía, sembrar kevix0813@yahoo.es / ProEspia2026
    total_usuarios = Usuario.query.count()
    if total_usuarios == 0:
        try:
            sa = Usuario(
                nombre='Kevin (Súper Admin)',
                username='kevix0813',
                correo=SUPER_ADMIN_CORREO,
                rol='admin',
                estado='Activo',
            )
            sa.set_password('ProEspia2026')
            db.session.add(sa)
            db.session.commit()
            print('=' * 60)
            print('SÚPER ADMIN CREADO AUTOMÁTICAMENTE')
            print(f'  Correo: {SUPER_ADMIN_CORREO}')
            print('  Clave:  ProEspia2026 (cámbiala al primer ingreso)')
            print('=' * 60)
        except Exception as e:
            db.session.rollback()
            print(f'Error creando súper admin: {e}')
    else:
        # Garantizar que kevix0813@yahoo.es exista siempre, con rol admin y estado Activo
        sa = Usuario.query.filter(func.lower(Usuario.correo) == SUPER_ADMIN_CORREO).first()
        if not sa:
            try:
                sa = Usuario(
                    nombre='Kevin (Súper Admin)',
                    username='kevix0813',
                    correo=SUPER_ADMIN_CORREO,
                    rol='admin',
                    estado='Activo',
                )
                sa.set_password('ProEspia2026')
                db.session.add(sa)
                db.session.commit()
                print('Súper Admin insertado (la tabla no estaba vacía).')
            except Exception as e:
                db.session.rollback()
                print(f'Error insertando súper admin: {e}')
        else:
            sa.rol = 'admin'
            sa.estado = 'Activo'
            if not sa.correo:
                sa.correo = SUPER_ADMIN_CORREO
            try:
                db.session.commit()
            except Exception:
                db.session.rollback()

    # Crear admin por defecto si no hay usuarios
    if not Usuario.query.first():
        admin = Usuario(username='admin', nombre='Administrador', rol='admin')
        admin.set_password('123')
        db.session.add(admin)
        db.session.commit()
        print('Admin por defecto creado: admin / 123')
    # Seed categorías de bodega si están vacías
    if not CategoriaItem.query.first():
        for nombre in ['Camaras', 'Conectividad', 'Discos Duros', 'Herramientas', 'Accesorios', 'Gabinetes', 'Fuentes de Poder', 'Cableado']:
            db.session.add(CategoriaItem(nombre=nombre))
        db.session.commit()
        print('Categorías de bodega creadas por defecto.')
    # Seed ubicación "Bodega Central" si está vacía
    if not Ubicacion.query.filter_by(nombre='Bodega Central').first():
        db.session.add(Ubicacion(nombre='Bodega Central', color='primary'))
        db.session.commit()
        print('Ubicación Bodega Central creada por defecto.')

# ==========================================
# 13. MANEJADORES DE ERROR (404 / 500)
# ==========================================
@app.errorhandler(404)
def page_not_found(e):
    try:
        if current_user.is_authenticated and current_user.puede_acceder():
            destino = url_for('dashboard', user_id=current_user.id)
        else:
            destino = url_for('login')
    except Exception:
        destino = '/'
    return render_template('errors/404.html',
                           status=404,
                           path=request.path,
                           destino=destino), 404


@app.errorhandler(500)
def internal_server_error(e):
    try:
        db.session.rollback()
    except Exception:
        pass
    print(f"[ERROR 500] {e}")
    return render_template('errors/500.html', status=500), 500


@app.errorhandler(403)
def forbidden(e):
    try:
        if current_user.is_authenticated and current_user.puede_acceder():
            destino = url_for('dashboard', user_id=current_user.id)
        else:
            destino = url_for('login')
    except Exception:
        destino = '/'
    return render_template('errors/404.html',
                           status=403,
                           path=request.path,
                           destino=destino), 403


@app.errorhandler(405)
def method_not_allowed(e):
    return render_template('errors/404.html',
                           status=405,
                           path=request.path,
                           destino=url_for('login')), 405


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)