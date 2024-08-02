# Create a virtual environment
python3 -m venv venv
# Activate the virtual environment
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
# upgrade pip
pip install --upgrade pip

# copy following lines to your requirements.txt
Flask==2.0.2
Jinja2==3.0.3
junos-eznc==2.6.4
lxml==4.6.4
Flask-SocketIO==5.1.1
Flask-SQLAlchemy==2.5.1
Flask-Login==0.5.0
Werkzeug==2.0.2
Flask-Migrate==3.1.0
ipaddress==1.0.23
flask-cors==3.0.10
websockets==10.1
SQLAlchemy==1.4.23
Flask-Script==2.0.6
# Install dependencies
pip install -r requirements.txt

# Setup database
rm -rf migrations/ # delete existing migrations
export FLASK_APP=app_generate_config.py
flask db init
flask db migrate -m "Initial migration."
flask db upgrade

(venv3) root@svl-jvision-srv01:~/easy_configuration# rm -rf migrations/
(venv3) root@svl-jvision-srv01:~/easy_configuration# flask db init
  Creating directory '/root/easy_configuration/migrations' ...  done
  Creating directory '/root/easy_configuration/migrations/versions' ...  done
  Generating /root/easy_configuration/migrations/README ...  done
  Generating /root/easy_configuration/migrations/alembic.ini ...  done
  Generating /root/easy_configuration/migrations/script.py.mako ...  done
  Generating /root/easy_configuration/migrations/env.py ...  done
  Please edit configuration/connection/logging settings in '/root/easy_configuration/migrations/alembic.ini' before proceeding.

(venv3) root@svl-jvision-srv01:~/easy_configuration# flask db migrate -m "Initial migration."
INFO  [alembic.runtime.migration] Context impl SQLiteImpl.
INFO  [alembic.runtime.migration] Will assume non-transactional DDL.
INFO  [alembic.autogenerate.compare] Detected added table 'user'
INFO  [alembic.autogenerate.compare] Detected added table 'device_info'
INFO  [alembic.autogenerate.compare] Detected added table 'topology'
INFO  [alembic.autogenerate.compare] Detected added table 'trigger_event'
  Generating /root/easy_configuration/migrations/versions/a68b01011974_initial_migration.py ...  done

(venv3) root@svl-jvision-srv01:~/easy_configuration# flask db upgrade
INFO  [alembic.runtime.migration] Context impl SQLiteImpl.
INFO  [alembic.runtime.migration] Will assume non-transactional DDL.
INFO  [alembic.runtime.migration] Running upgrade  -> a68b01011974, Initial migration.

## if you see Error
ERROR [flask_migrate] Error: Can't locate revision identified by 'a68b01011974'
python flask_db_drop.py
