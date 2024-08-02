"""Problem:
ERROR [flask_migrate] Error: Can't locate revision identified by '24898090fe18'

Flask DB Migration steps
#export FLASK_APP=app_generate_config.py
#flask db init
#flask db migrate -m "Initial migration with role column"
#flask db upgrade


"""


from app_generate_config import db, app
from app_generate_config import db, app

with app.app_context():
    db.drop_all()
    print("All tables dropped.")


from app_generate_config import db, app
from sqlalchemy import text

with app.app_context():
    with db.engine.connect() as connection:
        connection.execute(text('DROP TABLE IF EXISTS alembic_version'))
    print("Alembic version table dropped.")

