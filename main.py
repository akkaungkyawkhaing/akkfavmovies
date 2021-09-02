import os
import datetime as dt

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from jinja2 import select_autoescape
from flask_bootstrap import Bootstrap
from flask_wtf.csrf import CSRFProtect
from flask_migrate import Migrate
from flask_marshmallow import Marshmallow
from flask_cors import CORS


db = SQLAlchemy()
migrate = Migrate()
ma = Marshmallow()
cors = CORS()
csrf = CSRFProtect()
login_manager = LoginManager()


def create_app():
    """Application-factory pattern"""
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URI", "sqlite:///my_fav_movie.db")
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['PERMANENT_SESSION_LIFETIME'] = dt.timedelta(days=1)
    # To enable it globally
    app.jinja_env.autoescape = select_autoescape(
        default_for_string=True,
        default=True
    )

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    ma.init_app(app)
    cors.init_app(app)
    csrf.init_app(app)
    Bootstrap(app)
    login_manager.init_app(app)

    return app
