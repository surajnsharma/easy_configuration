from flask_script import Manager
from flask_migrate import MigrateCommand

from app_generate_config import app, db  # Import your app and db objects

manager = Manager(app)
manager.add_command('db', MigrateCommand)

if __name__ == '__main__':
    manager.run()

