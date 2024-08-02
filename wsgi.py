#!/usr/bin/python3.8
from app_generate_config import app, socketio


if __name__ == '__main__':
    socketio.run(app, debug=True, port=8080,host='0.0.0.0')
