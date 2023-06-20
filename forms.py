import wtforms.fields
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditorField


##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class UserRegisterationForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = wtforms.EmailField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField()


class UserLogInForm(FlaskForm):
    email = wtforms.EmailField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    Login = SubmitField("Login")


class CommentsForm(FlaskForm):
    body = CKEditorField("Add Comment", validators=[DataRequired()])
    comment = SubmitField("Comment")
