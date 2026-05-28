from app import app
from models import db, CategoriaItem, Ubicacion, Vehiculo

with app.app_context():
    db.create_all()

    cats = ['Camaras', 'Conectividad', 'Discos Duros', 'Herramientas', 'Accesorios', 'Gabinetes', 'Fuentes de Poder', 'Cableado']
    for c in cats:
        if not CategoriaItem.query.filter_by(nombre=c).first():
            db.session.add(CategoriaItem(nombre=c))

    ubs = [
        ('Bodega Central', 'primary', None),
        ('Camioneta ABC-123', 'warning', 'Toyota Hilux 2024'),
        ('Camioneta XYZ-789', 'warning', 'Nissan NP300 2023'),
    ]
    for nombre, color, modelo in ubs:
        u = Ubicacion.query.filter_by(nombre=nombre).first()
        if not u:
            u = Ubicacion(nombre=nombre, color=color)
            db.session.add(u)
            db.session.flush()
            print(f'  Ubicacion creada: {nombre}')
        if modelo:
            placa = nombre.replace('Camioneta ', '')
            if not Vehiculo.query.filter_by(placa=placa).first():
                db.session.add(Vehiculo(placa=placa, modelo=modelo, dia_checklist=4, ubicacion_id=u.id))
                print(f'    Vehiculo creado: {placa}')

    db.session.commit()
    print('Categorias, ubicaciones y vehiculos creados.')
