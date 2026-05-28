from app import app
from models import db, Vehiculo, Herramienta

with app.app_context():
    db.create_all()
    herramientas_base = [
        ('Taladro Inalambrico', 'TAL-001'),
        ('Escalera Telescopica', 'ESC-001'),
        ('Tester CCTV', 'TES-001'),
        ('Multimetro Digital', 'MUL-001'),
        ('Juego de Destornilladores', 'DES-001'),
        ('Ponchadora RJ45', 'PON-001'),
        ('Crimpadora Coaxial', 'CRI-001'),
        ('Linterna Recargable', 'LIN-001'),
        ('Cinta Metrica 5m', 'CIN-001'),
        ('Nivel Laser', 'NIV-001'),
    ]
    vehiculos = Vehiculo.query.all()
    if not vehiculos:
        print('No hay vehiculos. Ejecuta crear_bodega.py primero.')
        exit()
    for v in vehiculos:
        count = 0
        for nombre, codigo in herramientas_base:
            existe = Herramienta.query.filter_by(vehiculo_id=v.id, codigo_inventario=codigo).first()
            if not existe:
                codigo_vehiculo = f'{codigo}-{v.id}'
                db.session.add(Herramienta(nombre=nombre, codigo_inventario=codigo_vehiculo, vehiculo_id=v.id))
                count += 1
        print(f'  {v.placa}: {count} herramienta(s) agregada(s)')
    db.session.commit()
    total = Herramienta.query.count()
    print(f'Total herramientas en DB: {total}')
