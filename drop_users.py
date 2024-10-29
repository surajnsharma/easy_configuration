from app import create_app, db
from app.models import User

# Create the app with the appropriate config
app = create_app('development')

with app.app_context():
    # Drop all users from the User table
    User.query.delete()
    db.session.commit()
    print("All users have been deleted.")

