from app import app, db, User
from sqlalchemy.exc import SQLAlchemyError
import logging
import time
from sqlalchemy import text

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def wait_for_db():
    max_retries = 30
    retry_interval = 2

    for i in range(max_retries):
        try:
            # Try to connect and run a simple query
            with app.app_context():
                db.session.execute(text('SELECT 1'))
                db.session.commit()
                logger.info("Database is available!")
                return True
        except Exception as e:
            if i < max_retries - 1:
                logger.warning(f"Database not ready (attempt {i + 1}/{max_retries}): {str(e)}")
                time.sleep(retry_interval)
            else:
                logger.error("Max retries reached. Database is not available.")
                raise

def init_db():
    try:
        # Wait for database to be ready
        wait_for_db()
        
        with app.app_context():
            # Drop all tables first to ensure clean state
            logger.info("Dropping all tables...")
            db.drop_all()
            db.session.commit()
            
            # Create all tables
            logger.info("Creating all tables...")
            db.create_all()
            db.session.commit()
            
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
        db.session.rollback()
        raise
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        db.session.rollback()
        raise

if __name__ == '__main__':
    init_db()
