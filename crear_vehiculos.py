from app import app
from models import db, Vehiculo, Ubicacion

with app.app_context():
    db.create_all()
    camionetas = Ubicacion.query.filter(Ubicacion.nombre.like('Camioneta%')).all()
    count = 0
    for u in camionetas:
        existe = Vehiculo.query.filter_by(ubicacion_id=u.id).first()
        if not existe:
            placa = u.nombre.replace('Camioneta ', '')
            v = Vehiculo(placa=placa, modelo='—', dia_checklist=4, ubicacion_id=u.id)
            db.session.add(v)
            count += 1
            print(f'  Creado vehículo: {v.placa} -> {u.nombre}')
    if count == 0:
        print('No hay camionetas nuevas que migrar.')
    db.session.commit()
    print(f'{count} vehículo(s) creado(s) desde ubicaciones existentes.')
