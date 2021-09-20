from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired, Length, EqualTo, Email


class FindMovieForm(FlaskForm):
    movie_title = StringField('', validators=[DataRequired()])
    # submit = SubmitField('search')


class RegisterForm(FlaskForm):
    name = StringField(validators=[DataRequired(), Length(min=4)])
    email = EmailField(validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField(validators=[DataRequired(),
                                         Length(min=8, message='Password should be at least %(min)d characters long')])
    repeat_password = PasswordField(validators=[DataRequired(message='*Required'),
                                                EqualTo('password',
                                                        message='Passwords must match!')])

    # def validate_username(self, name):
    #     excluded_chars = " *?!'^+%&/()=}][{$#"
    #     for char in self.name.data:
    #         if char in excluded_chars:
    #             raise ValidationError(f"Character {char} is not allowed in username.")


class LoginForm(FlaskForm):
    email = EmailField(validators=[DataRequired(), Email()])
    password = PasswordField(validators=[DataRequired()])
