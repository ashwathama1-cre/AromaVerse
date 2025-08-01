# forms.py

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField, DecimalField
from wtforms.validators import DataRequired, Email, EqualTo, Length, NumberRange

# Login Form
class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=30)])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

# Registration Form
class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=30)])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo('password')])
    role = SelectField("Role", choices=[('buyer', 'Buyer'), ('seller', 'Seller')], validators=[DataRequired()])
    submit = SubmitField("Register")

# Product Upload Form (for Sellers)
class ProductForm(FlaskForm):
    name = StringField("Product Name", validators=[DataRequired()])
    scent_type = SelectField("Scent Type", choices=[
        ('rose', 'Rose'),
        ('musk', 'Musk'),
        ('jasmine', 'Jasmine'),
        ('sandalwood', 'Sandalwood'),
        ('other', 'Other')
    ], validators=[DataRequired()])
    quantity = DecimalField("Quantity", validators=[DataRequired(), NumberRange(min=0)])
    unit = SelectField("Unit", choices=[('ml', 'ml'), ('gm', 'gm'), ('bottle', 'Bottle')], validators=[DataRequired()])
    price = DecimalField("Price (₹)", validators=[DataRequired(), NumberRange(min=0)])
    description = TextAreaField("Description", validators=[Length(max=300)])
    submit = SubmitField("Add Product")

# Complaint / Contact Form
class ComplaintForm(FlaskForm):
    subject = StringField("Subject", validators=[DataRequired()])
    message = TextAreaField("Message", validators=[DataRequired(), Length(max=500)])
    submit = SubmitField("Submit")

# Search / Filter Form
class SearchForm(FlaskForm):
    keyword = StringField("Search Products", validators=[Length(max=50)])
    scent_type = SelectField("Filter by Type", choices=[
        ('', 'All'),
        ('rose', 'Rose'),
        ('musk', 'Musk'),
        ('jasmine', 'Jasmine'),
        ('sandalwood', 'Sandalwood'),
        ('other', 'Other')
    ])
    submit = SubmitField("Filter")


from wtforms import BooleanField

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=30)])
    password = PasswordField("Password", validators=[DataRequired()])
    remember = BooleanField("Remember Me")   # ✅ Add this line
    submit = SubmitField("Login")

