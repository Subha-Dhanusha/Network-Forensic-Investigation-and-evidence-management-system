import os
from flask import Flask
from flask_migrate import Migrate
from .models import db


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    instance_dir = os.path.join(base_dir, "app", "instance")
    os.makedirs(instance_dir, exist_ok=True)

    database_url = os.environ.get("DATABASE_URL", "")
    if database_url.startswith("postgres://"):
        # Render (and Heroku-style providers) give postgres://, but
        # SQLAlchemy 2.x requires the postgresql:// scheme.
        database_url = database_url.replace("postgres://", "postgresql://", 1)

    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-change-me"),
        SQLALCHEMY_DATABASE_URI=database_url or f"sqlite:///{os.path.join(instance_dir, 'nfies.db')}",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        UPLOAD_FOLDER=os.path.join(base_dir, "app", "uploads"),
        EXTRACTED_FOLDER=os.path.join(base_dir, "app", "extracted"),
        REPORTS_FOLDER=os.path.join(base_dir, "app", "reports"),
        MAX_CONTENT_LENGTH=500 * 1024 * 1024,
        VT_API_KEY=os.environ.get("VT_API_KEY", ""),
    )

    if test_config:
        app.config.update(test_config)

    for folder_key in ("UPLOAD_FOLDER", "EXTRACTED_FOLDER", "REPORTS_FOLDER"):
        os.makedirs(app.config[folder_key], exist_ok=True)

    db.init_app(app)
    Migrate(app, db)

    from . import routes
    app.register_blueprint(routes.bp)

    return app