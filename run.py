#run.py#
from app import create_app, socketio
import os
config_name = os.getenv('FLASK_CONFIG') or 'development'

app = create_app(config_name)
if __name__ == '__main__':
    #socketio.run(app)
    socketio.run(app, host='0.0.0.0', port=5001)
