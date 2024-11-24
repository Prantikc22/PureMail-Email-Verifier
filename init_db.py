from app import app, db, User
from sqlalchemy.exc import SQLAlchemyError
import logging
import time
from sqlalchemy import text

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
    """Initialize the database with tables and initial data."""
    try:
        # Wait for database to be ready
        wait_for_db()
        
        # Create all tables
        with app.app_context():
            db.create_all()
            logger.info("Successfully created all database tables")

            # Check if admin user exists
            admin = User.query.filter_by(email='admin@puremail.com').first()
            if not admin:
                # Create admin user
                admin = User(
                    username='admin@puremail.com',
                    email='admin@puremail.com',
                    is_admin=True,
                    credits=1000
                )
                admin.set_password('admin123')
                db.session.add(admin)
                db.session.commit()
                logger.info("Successfully created admin user")

            logger.info("Database initialization completed successfully")
            return True

    except Exception as e:
        logger.error(f"Error initializing database: {str(e)}")
        db.session.rollback()
        return False

if __name__ == '__main__':
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger(__name__)

    # Initialize Flask app context
    with app.app_context():
        success = init_db()
        if success:
            logger.info("Database initialization successful")
        else:
            logger.error("Database initialization failed")
