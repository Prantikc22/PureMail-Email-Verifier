from app import app, db, User
from sqlalchemy.exc import SQLAlchemyError
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def init_db():
    try:
        with app.app_context():
            # Drop all tables first to ensure clean state
            logger.info("Dropping all tables...")
            db.drop_all()
            
            # Create all tables
            logger.info("Creating all tables...")
            db.create_all()
            
            # Check if admin user exists
            logger.info("Checking for admin user...")
            admin = User.query.filter_by(id=1).first()
            if not admin:
                admin = User(
                    id=1,
                    username='admin@puremail.com',
                    email='admin@puremail.com'
                )
                admin.set_password('admin123')
                db.session.add(admin)
                db.session.commit()
                logger.info("Admin user created successfully")
            else:
                logger.info("Admin user already exists")
                
    except SQLAlchemyError as e:
        logger.error(f"Database error occurred: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        raise

if __name__ == '__main__':
    init_db()
