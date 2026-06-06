"""
Limpia toda la base de datos y deja SOLO al Súper Admin (kevix0813@yahoo.es).
Funciona en local (SQLite) y en producción (PostgreSQL en Render).

USO:
  Local:
    python wipe_db.py --confirmar
  Render (web shell):
    python wipe_db.py --confirmar
"""
import os
import sys
import argparse
from app import app
from models import (
    db, Usuario, Cliente, Equipo, Bitacora, Boveda, VisitaProgramada,
    CategoriaItem, Ubicacion, ProductoStock, MovimientoStock, Vehiculo,
    Herramienta, ChecklistSemanal, SolicitudCombustible, PushSubscription,
    Notificacion, RegistroIP, SUPER_ADMIN_CORREO
)
from werkzeug.security import generate_password_hash

# Tablas a vaciar en el orden correcto (hijos antes que padres para FKs)
TABLAS_LIMPIAR = [
    'notificacion',
    'push_subscription',
    'solicitud_combustible',
    'checklist_semanal',
    'herramienta',
    'movimiento_stock',
    'producto_stock',
    'vehiculo',
    'ubicacion_bodega',
    'categoria_item',
    'visita_programada',
    'boveda',
    'bitacora',
    'equipo',
    'cliente',
    'tarea',
    'registro_ip',
]

def confirmar(conteo):
    total = sum(conteo.values())
    print("\n" + "=" * 60)
    print("LIMPIEZA TOTAL DE BASE DE DATOS")
    print("=" * 60)
    print(f"\nSe ELIMINARÁN todas las filas de {total} tablas (excepto `usuario`).\n")
    for tabla, n in conteo.items():
        print(f"  · {n:>5} filas en {tabla}")
    print(f"\nSe conservará solo al Súper Admin: {SUPER_ADMIN_CORREO}")
    print("=" * 60)


def run(confirmado=False):
    with app.app_context():
        # Conteos previos
        conteo = {}
        for tabla in TABLAS_LIMPIAR:
            try:
                n = db.session.execute(db.text(f"SELECT COUNT(*) FROM {tabla}")).scalar()
                conteo[tabla] = n or 0
            except Exception as e:
                conteo[tabla] = f"err: {e}"

        confirmar(conteo)

        if not confirmado:
            print("\n⚠️  Operación CANCELADA (usa --confirmar para ejecutar).")
            return

        print("\n🧹 Limpiando tablas...")
        for tabla in TABLAS_LIMPIAR:
            try:
                filas = db.session.execute(db.text(f"DELETE FROM {tabla}")).rowcount
                print(f"  ✓ {tabla}: {filas} filas eliminadas")
            except Exception as e:
                print(f"  ⚠️  {tabla}: {e}")
                db.session.rollback()
                continue

        # Resetear secuencia de autoincrement (PostgreSQL) o sqlite_sequence
        try:
            db.session.execute(db.text("DELETE FROM sqlite_sequence"))
            print("  ✓ sqlite_sequence reiniciado")
        except Exception:
            pass
        try:
            for tabla in TABLAS_LIMPIAR:
                db.session.execute(db.text(
                    f"SELECT setval(pg_get_serial_sequence('{tabla}', 'id'), 1, false)"
                ))
        except Exception:
            pass

        # Eliminar todos los usuarios EXCEPTO el Súper Admin
        print("\n👤 Limpiando usuarios (excepto Súper Admin)...")
        try:
            super_admin = Usuario.query.filter(
                db.func.lower(Usuario.correo) == SUPER_ADMIN_CORREO
            ).first()

            # Borrar todos los usuarios que no son el súper admin
            usuarios_borrados = Usuario.query.filter(
                db.or_(
                    Usuario.correo.is_(None),
                    db.func.lower(Usuario.correo) != SUPER_ADMIN_CORREO
                )
            ).all()
            n_users = len(usuarios_borrados)
            for u in usuarios_borrados:
                db.session.delete(u)
            db.session.commit()
            print(f"  ✓ {n_users} usuarios eliminados")

            # Si no existe el súper admin, crearlo
            if not super_admin:
                super_admin = Usuario(
                    nombre='Kevin (Súper Admin)',
                    username='kevix0813',
                    correo=SUPER_ADMIN_CORREO,
                    rol='admin',
                    estado='Activo',
                )
                super_admin.set_password('ProEspia2026')
                db.session.add(super_admin)
                db.session.commit()
                print("  ✓ Súper Admin creado: kevix0813@yahoo.es / ProEspia2026")
            else:
                # Garantizar que el súper admin esté correcto
                super_admin.rol = 'admin'
                super_admin.estado = 'Activo'
                if not super_admin.correo:
                    super_admin.correo = SUPER_ADMIN_CORREO
                super_admin.password = generate_password_hash('ProEspia2026')
                super_admin.nombre = super_admin.nombre or 'Kevin (Súper Admin)'
                super_admin.username = super_admin.username or 'kevix0813'
                db.session.commit()
                print("  ✓ Súper Admin preservado y contraseña reseteada a 'ProEspia2026'")
        except Exception as e:
            db.session.rollback()
            print(f"  ❌ Error con usuarios: {e}")
            raise

        # Re-seed categorías de bodega
        print("\n📦 Re-sembrando categorías de bodega...")
        for nombre in ['Camaras', 'Conectividad', 'Discos Duros', 'Herramientas',
                       'Accesorios', 'Gabinetes', 'Fuentes de Poder', 'Cableado']:
            db.session.add(CategoriaItem(nombre=nombre))
        db.session.commit()
        print(f"  ✓ {8} categorías creadas")

        # Re-seed ubicación Bodega Central
        print("\n📍 Re-sembrando ubicación Bodega Central...")
        db.session.add(Ubicacion(nombre='Bodega Central', color='primary'))
        db.session.commit()
        print("  ✓ Bodega Central creada")

        print("\n" + "=" * 60)
        print("✅ LIMPIEZA COMPLETADA")
        print("=" * 60)
        print(f"\n  Login:    {SUPER_ADMIN_CORREO}")
        print(f"  Password: ProEspia2026")
        print(f"  URL:      {os.environ.get('RENDER_EXTERNAL_URL', 'https://proespia-app.onrender.com')}")
        print("\n⚠️  Cambia la contraseña al primer ingreso.")
        print("=" * 60)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Limpia la base de datos y deja solo al Súper Admin.')
    parser.add_argument('--confirmar', action='store_true',
                        help='Confirma la ejecución (sin esto, solo muestra el preview).')
    args = parser.parse_args()
    run(confirmado=args.confirmar)
