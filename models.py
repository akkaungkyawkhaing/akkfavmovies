from flask_login import UserMixin
from main import db, ma


# Create Table
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))


class Movie(db.Model):
    __tablename__ = "movies"
    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    release_date = db.Column(db.Integer, nullable=False)
    runtime = db.Column(db.Integer, nullable=False)
    tagline = db.Column(db.String(100), nullable=False)
    overview = db.Column(db.String(2500), nullable=False)
    vote_average = db.Column(db.Float, nullable=False)
    ranking = db.Column(db.Float, nullable=False)
    genres = db.Column(db.String(50), nullable=False)
    original_language = db.Column(db.String(10), nullable=False)
    poster_path = db.Column(db.String(250), nullable=False)
    backdrop_path = db.Column(db.String(250), nullable=False)


# Generate marshmallow Schemas from your models
class UsersShema(ma.Schema):
    class Meta:
        # Fields to expose
        fields = ("id", "name", "email", "password")


class MoviesShema(ma.Schema):
    class Meta:
        # Fields to expose
        fields = ("id", "org_id", "title", "release_date", "runtime", "tagline", "overview",
                  "vote_average", "ranking", "genres", "original_language", "poster_path",
                  "backdrop_path")


user_schema = UsersShema()
users_schema = UsersShema(many=True)
movie_schema = MoviesShema()
movies_schema = MoviesShema(many=True)