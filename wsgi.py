from app import app as application
from config import ProductionConfig

application.config.from_object(ProductionConfig)

if __name__ == "__main__":
    application.run()
