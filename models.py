from flask_login import UserMixin
from main import db, ma


# Create Table
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

    # def __init__(self, name, email, password):
    #     self.name = name
    #     self.email = email
    #     self.password = password


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
class UsersSchema(ma.Schema):
    class Meta:
        # Fields to expose
        fields = ("id", "name", "email", "password")


class MoviesSchema(ma.Schema):
    class Meta:
        # Fields to expose
        fields = ("id", "org_id", "title", "release_date", "runtime", "tagline", "overview",
                  "vote_average", "ranking", "genres", "original_language", "poster_path",
                  "backdrop_path")


# init schema
user_schema = UsersSchema()
users_schema = UsersSchema(many=True)

movie_schema = MoviesSchema()
movies_schema = MoviesSchema(many=True)