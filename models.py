from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import base64
import hashlib
db = SQLAlchemy()

def get_fernet(app):
    raw = app.config['SECRET_KEY'].encode()
    key = base64.urlsafe_b64encode(hashlib.sha256(raw).digest())
    return Fernet(key)

class Usuario(db.Model, UserMixin):
    def set_password(self, password):
        """Transforma la clave plana en un hash seguro."""
        self.password = generate_password_hash(password)

    def check_password(self, password):
        """Compara la clave ingresada con el hash guardado."""
        return check_password_hash(self.password, password)
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    rol = db.Column(db.String(20), default='tecnico')
    ubicacion_id = db.Column(db.Integer, db.ForeignKey('ubicacion_bodega.id'), nullable=True)
    tipo_asignacion = db.Column(db.String(20), default='acompanante')  # 'a_cargo' o 'acompanante'

    rel_ubicacion = db.relationship('Ubicacion', backref='usuarios_asignados') 
    
    # RELACIÓN DE USUARIO A BITÁCORA
    # Cambiamos el backref a 'rel_usuario' para que coincida con tu HTML
    entradas_bitacora = db.relationship('Bitacora', backref='rel_usuario', lazy=True) 

class Cliente(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100))
    direccion = db.Column(db.String(200))
    plan_cuadrante = db.Column(db.String(20))
    contacto_emergencia = db.Column(db.String(500), nullable=True)
    estado_monitoreo = db.Column(db.String(50), default='En Instalación')
    latitud = db.Column(db.Float, nullable=True)
    longitud = db.Column(db.Float, nullable=True)
    
    # NOTA: No definimos 'equipos' ni 'bitacoras' aquí. 
    # Se crearán automáticamente gracias al 'backref' en los otros modelos.

class Equipo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cliente_id = db.Column(db.Integer, db.ForeignKey('cliente.id'))
    tipo = db.Column(db.String(50)) 
    serie = db.Column(db.String(100), unique=True)
    ip = db.Column(db.String(50))
    usuario_equipo = db.Column(db.String(50))
    pass_equipo = db.Column(db.String(100))
    ubicacion = db.Column(db.String(100)) 

    # RELACIÓN ÚNICA: 
    # Usamos 'rel_cliente' para el equipo (e.rel_cliente.nombre)
    # Usamos 'rel_cliente_equipos' para el cliente (c.rel_cliente_equipos)
    rel_cliente = db.relationship('Cliente', backref='rel_cliente_equipos')

class Bitacora(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fecha = db.Column(db.DateTime, default=datetime.now)
    tipo_visita = db.Column(db.String(50))
    descripcion = db.Column(db.Text)
    informe_tecnico = db.Column(db.Text)
    foto_falla = db.Column(db.String(200))
    fecha_resolucion = db.Column(db.DateTime)
    
    cliente_id = db.Column(db.Integer, db.ForeignKey('cliente.id'))
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'))
    
    # Nueva columna: 1=Crítica, 2=Alta, 3=Media, 4=Baja
    # Por defecto será 3 (Media) para no romper los registros que ya tienes
    prioridad = db.Column(db.Integer, default=3)
    rel_cliente = db.relationship('Cliente', backref='bitacoras')
    
class Tarea(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(100), nullable=False)
    # 1=Crítico, 2=Alto, 3=Medio
    prioridad = db.Column(db.Integer, default=3) 
    estado = db.Column(db.String(20), default='Pendiente') 
    fecha_creacion = db.Column(db.DateTime, default=datetime.now)

class Boveda(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre_app = db.Column(db.String(100), nullable=False)
    url_acceso = db.Column(db.String(200))
    usuario_app = db.Column(db.String(100))
    password_app = db.Column(db.Text, nullable=False)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id')) 
    
    propietario = db.relationship('Usuario', backref='mis_claves')

    @staticmethod
    def encrypt_password(plain_password):
        from flask import current_app
        f = get_fernet(current_app)
        return f.encrypt(plain_password.encode()).decode()

    def decrypt_password(self):
        from flask import current_app
        f = get_fernet(current_app)
        try:
            return f.decrypt(self.password_app.encode()).decode()
        except Exception:
            return self.password_app
    
class VisitaProgramada(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cliente_id = db.Column(db.Integer, db.ForeignKey('cliente.id'), nullable=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)
    fecha_programada = db.Column(db.DateTime, nullable=False)
    tipo_trabajo = db.Column(db.String(100), nullable=False)
    descripcion = db.Column(db.Text, nullable=True)
    ubicacion = db.Column(db.String(500), nullable=True)
    estado = db.Column(db.String(20), default='Pendiente')
    informe_tecnico = db.Column(db.Text, nullable=True)
    fecha_completada = db.Column(db.DateTime, nullable=True)
    foto_visita = db.Column(db.String(255), nullable=True)
    
    # Relaciones
    rel_cliente = db.relationship('Cliente', backref='visitas_programadas')
    rel_usuario = db.relationship('Usuario', backref='visitas_asignadas')

# ==========================================
# MÓDULO DE BODEGA Y STOCK TÉCNICO
# ==========================================
class CategoriaItem(db.Model):
    __tablename__ = 'categoria_item'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(80), nullable=False, unique=True)

class Ubicacion(db.Model):
    __tablename__ = 'ubicacion_bodega'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False, unique=True)
    color = db.Column(db.String(20), default='primary')

class ProductoStock(db.Model):
    __tablename__ = 'producto_stock'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(120), nullable=False)
    marca = db.Column(db.String(80))
    modelo = db.Column(db.String(80))
    cantidad_actual = db.Column(db.Integer, default=0)
    cantidad_minima = db.Column(db.Integer, default=1)
    valor_estimado = db.Column(db.Integer, default=0)
    estado = db.Column(db.String(20), default='Nuevo')
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

    categoria_id = db.Column(db.Integer, db.ForeignKey('categoria_item.id'), nullable=True)
    ubicacion_id = db.Column(db.Integer, db.ForeignKey('ubicacion_bodega.id'), nullable=True)

    rel_categoria = db.relationship('CategoriaItem', backref='productos')
    rel_ubicacion = db.relationship('Ubicacion', backref='productos')

class MovimientoStock(db.Model):
    __tablename__ = 'movimiento_stock'
    id = db.Column(db.Integer, primary_key=True)
    tipo = db.Column(db.String(20), nullable=False)
    cantidad = db.Column(db.Integer, nullable=False)
    descripcion = db.Column(db.Text)
    fecha = db.Column(db.DateTime, default=datetime.now)

    producto_id = db.Column(db.Integer, db.ForeignKey('producto_stock.id'), nullable=False)
    desde_ubicacion_id = db.Column(db.Integer, db.ForeignKey('ubicacion_bodega.id'), nullable=True)
    hacia_ubicacion_id = db.Column(db.Integer, db.ForeignKey('ubicacion_bodega.id'), nullable=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=True)

    rel_producto = db.relationship('ProductoStock', backref='movimientos')
    rel_desde = db.relationship('Ubicacion', foreign_keys=[desde_ubicacion_id])
    rel_hacia = db.relationship('Ubicacion', foreign_keys=[hacia_ubicacion_id])
    rel_usuario = db.relationship('Usuario', backref='movimientos_stock')

class Vehiculo(db.Model):
    __tablename__ = 'vehiculo'
    id = db.Column(db.Integer, primary_key=True)
    placa = db.Column(db.String(20), unique=True, nullable=False)
    modelo = db.Column(db.String(80))
    dia_checklist = db.Column(db.Integer, default=4)
    created_at = db.Column(db.DateTime, default=datetime.now)

    ubicacion_id = db.Column(db.Integer, db.ForeignKey('ubicacion_bodega.id'), nullable=True)
    rel_ubicacion = db.relationship('Ubicacion', backref=db.backref('vehiculo', uselist=False))

    herramientas = db.relationship('Herramienta', backref='rel_vehiculo', lazy=True)

class Herramienta(db.Model):
    __tablename__ = 'herramienta'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(120), nullable=False)
    codigo_inventario = db.Column(db.String(50), unique=True, nullable=False)
    vehiculo_id = db.Column(db.Integer, db.ForeignKey('vehiculo.id'), nullable=False)

class ChecklistSemanal(db.Model):
    __tablename__ = 'checklist_semanal'
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)
    vehiculo_id = db.Column(db.Integer, db.ForeignKey('vehiculo.id'), nullable=False)
    fecha_registro = db.Column(db.DateTime, default=datetime.now)
    estado_completo = db.Column(db.Boolean, default=True)
    observaciones = db.Column(db.Text)
    herramientas_ok = db.Column(db.Text, nullable=True)

    rel_usuario = db.relationship('Usuario', backref='checklists')
    rel_vehiculo = db.relationship('Vehiculo', backref='checklists')

class SolicitudCombustible(db.Model):
    __tablename__ = 'solicitud_combustible'
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)
    vehiculo_id = db.Column(db.Integer, db.ForeignKey('vehiculo.id'), nullable=True)
    monto = db.Column(db.Integer, nullable=False)
    kilometraje = db.Column(db.Integer, default=0)
    estado = db.Column(db.String(20), default='Pendiente')
    created_at = db.Column(db.DateTime, default=datetime.now)

    rel_usuario = db.relationship('Usuario', backref='solicitudes_combustible')
    rel_vehiculo = db.relationship('Vehiculo', backref='solicitudes_combustible')

class PushSubscription(db.Model):
    __tablename__ = 'push_subscription'
    id = db.Column(db.Integer, primary_key=True)
    endpoint = db.Column(db.Text, nullable=False)
    auth = db.Column(db.String(200), nullable=False)
    p256dh = db.Column(db.String(200), nullable=False)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now)

    rel_usuario = db.relationship('Usuario', backref='push_subscriptions')

class Notificacion(db.Model):
    __tablename__ = 'notificacion'
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)
    titulo = db.Column(db.String(200), nullable=False)
    mensaje = db.Column(db.Text, nullable=True)
    url = db.Column(db.String(500), nullable=True)
    leida = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    tipo = db.Column(db.String(30), default='info')

    rel_usuario = db.relationship('Usuario', backref='notificaciones')