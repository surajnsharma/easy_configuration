# Create a virtual environment
python3 -m venv venv
# Activate the virtual environment
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
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

# Install dependencies
pip install -r requirements.txt
