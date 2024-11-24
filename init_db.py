from app import app, db, User
from flask_migrate import upgrade

def init_db():
    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Check if admin user exists
        admin = User.query.filter_by(id=1).first()
        if not admin:
            admin = User(
                id=1,
                username='admin',
                email='admin@puremail.com'
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print("Admin user created successfully")
        else:
            print("Admin user already exists")

if __name__ == '__main__':
    init_db()
