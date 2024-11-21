from app import app, db, User
from werkzeug.security import generate_password_hash

def check_and_fix_users():
    with app.app_context():
        # Check existing users
        users = User.query.all()
        print("Current users:", [{'username': u.username, 'email': u.email} for u in users])
        
        # Reset password for the first user
        if users:
            user = users[0]  # Get the first user
            new_password = 'password123'  # Set a known password
            user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
            db.session.commit()
            print(f"Reset password for user '{user.username}' to: '{new_password}'")
        else:
            print("No users found in the database.")

if __name__ == '__main__':
    check_and_fix_users()
