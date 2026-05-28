# Proespia Gestión

Sistema de gestión para empresa de seguridad electrónica. Control de inventario, clientes, bitácora de visitas técnicas, agenda de terreno, bóveda de contraseñas y notificaciones push.

## Stack

- **Backend:** Flask + SQLAlchemy + SQLite (dev) / PostgreSQL (prod)
- **Auth:** Flask-Login (roles: admin, super_su, operador, tecnico)
- **Frontend:** Bootstrap 5 + Tailwind (legado) + Font Awesome 6
- **Notificaciones:** Web Push (pywebpush)
- **PDF:** fpdf2

## Requisitos

- Python 3.11+

## Instalación local

```powershell
git clone https://github.com/KevinAntoniooo/proespia.app.git
cd proespia.app
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Abrir `http://127.0.0.1:5000`

## Seed data (local)

Los scripts de seed no están incluidos en el repo. Para crear datos de prueba:

```python
# Desde consola Flask
from app import app, db
from models import Usuario
with app.app_context():
    admin = Usuario(username='admin', rol='admin')
    admin.set_password('123')
    db.session.add(admin)
    db.session.commit()
```

## Deploy en Render

1. Crear Web Service desde el repo de GitHub
2. Agregar variable `DATABASE_URL` con Internal URL de PostgreSQL
3. Agregar variable `SECRET_KEY`
4. Deploy automático en cada push a `main`

## Variables de entorno

| Variable | Descripción |
|---|---|
| `DATABASE_URL` | URI de PostgreSQL (producción) o SQLite (local) |
| `SECRET_KEY` | Clave secreta de Flask |

## Licencia

Uso interno — Proespia Ltda.
