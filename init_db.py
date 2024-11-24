import os
from app import app, db, User
from sqlalchemy.exc import SQLAlchemyError
import logging
import time
from sqlalchemy import text

def wait_for_db():
    """Wait for database to be ready"""
    max_retries = 30
    retry_interval = 2

    for i in range(max_retries):
        try:
            # Try to connect to the database
            with app.app_context():
                db.session.execute(text('SELECT 1'))
                logger.info("Database connection successful")
                return True
        except Exception as e:
            if i < max_retries - 1:
                logger.warning(f"Database not ready, retrying in {retry_interval} seconds... ({str(e)})")
                time.sleep(retry_interval)
            else:
                logger.error(f"Max retries reached. Database is not available: {str(e)}")
                return False

def init_db():
    """Initialize the database with tables and initial data"""
    try:
        # Wait for database to be ready
        if not wait_for_db():
            logger.error("Failed to connect to database")
            return False

        with app.app_context():
            # Create all tables
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
        if 'db' in locals() and hasattr(db, 'session'):
            db.session.rollback()
        return False

if __name__ == '__main__':
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger(__name__)

    # Log environment information
    logger.info(f"DATABASE_URL: {os.environ.get('DATABASE_URL', 'Not set')}")
    logger.info(f"FLASK_ENV: {os.environ.get('FLASK_ENV', 'Not set')}")

    # Initialize database
    success = init_db()
    if success:
        logger.info("Database initialization successful")
        exit(0)
    else:
        logger.error("Database initialization failed")
        exit(1)
