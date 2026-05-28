from app import app
from models import db, Usuario

with app.app_context():
    # 1. Opcional: Esto creará las tablas de nuevo si borraste el archivo .db
    db.create_all()

    # 2. Creamos tu usuario administrador con Hashing
    nuevo_admin = Usuario(
        nombre="Kevin",
        username="admin",
        rol="admin"
    )
    
    # IMPORTANTE: Aquí usamos la función que encripta la clave
    nuevo_admin.set_password("123") 
    
    try:
        db.session.add(nuevo_admin)
        db.session.commit()
        print("¡Usuario administrador 'admin' creado con éxito y clave encriptada!")
    except Exception as e:
        db.session.rollback()
        print(f"Error al crear el admin: {e}")