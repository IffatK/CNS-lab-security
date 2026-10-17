from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, TextAreaField, ValidationError
from wtforms.validators import DataRequired, EqualTo, Length, Regexp

USERNAME_RE = r"^[A-Za-z0-9_]{3,32}$"


class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[
        DataRequired(), Length(min=3, max=32),
        Regexp(USERNAME_RE, message="Use 3-32 letters, digits or underscores.")])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=10, max=128)])
    confirm = PasswordField("Confirm password", validators=[DataRequired(), EqualTo("password", "Passwords must match.")])

    def validate_password(self, field):
        pw = field.data or ""
        if (self.username.data or "").lower() in pw.lower():
            raise ValidationError("Password must not contain the username.")
        if pw.isdigit() or pw.isalpha():
            raise ValidationError("Password must mix letters and non-letters.")


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(max=64)])
    password = PasswordField("Password", validators=[DataRequired(), Length(max=128)])


class ComposeForm(FlaskForm):
    recipient = StringField("Recipient username", validators=[DataRequired(), Length(min=3, max=32)])
    body = TextAreaField("Message", validators=[DataRequired(), Length(max=2000)])
