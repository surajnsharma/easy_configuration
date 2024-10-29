export FLASK_APP="app:create_app('development')" 
flask db init
flask db migrate -m " "
flask db upgrade

