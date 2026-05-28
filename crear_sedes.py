from app import app
from models import db, Cliente

with app.app_context():
    # Creamos un par de sedes de ejemplo en la zona
    sede1 = Cliente(
        nombre="Mall Vivo Rancagua", 
        direccion="Sanjofre 450", 
        plan_cuadrante="912345678",
        estado_monitoreo="Activo"
    )
    sede2 = Cliente(
        nombre="Condominio Los Lirios", 
        direccion="Ruta 5 Sur, Requínoa", 
        plan_cuadrante="987654321",
        estado_monitoreo="En Instalación"
    )

    db.session.add(sede1)
    db.session.add(sede2)
    db.session.commit()
    print("¡Sedes de prueba creadas con éxito!")