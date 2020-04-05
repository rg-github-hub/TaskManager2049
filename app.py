from flask import Flask, render_template, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, BooleanField, RadioField, IntegerField, DecimalField, SelectField, PasswordField, SubmitField
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:Param123@localhost/png'
db = SQLAlchemy(app)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
login = LoginManager(app)
Bootstrap(app)
app.config['SECRET_KEY'] = 'dsfsgregsd'

class User(UserMixin, db.Model):
    """Model for user accounts."""

    __tablename__ = 'flasklogin-users'


    id = db.Column(db.String(10),
                     nullable=False,
                     unique=True,
                     primary_key=True)

    password = db.Column(db.String(200),
                         primary_key=False,
                         unique=False,
                         nullable=False)

    def set_password(self, password):
        """Create hashed password."""
        self.password = generate_password_hash(password, method='sha256')

    def check_password(self, password):
        """Check hashed password."""
        return check_password_hash(self.password, password)

    def __repr__(self):
        return '<User {}>'.format(self.username)

@login.user_loader
def load_user(username):
    return User.query.get(username)


class SignupForm(FlaskForm):
    """User Signup Form."""
    name = StringField('Name')
    email = StringField('Email')
    password = PasswordField('Password')
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    """User Login Form."""
    username = StringField('Email')
    password = PasswordField('Password')
    submit = SubmitField('Log In')


@app.route('/login', methods=['GET', 'POST'])
def login_page():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(id=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password',category="danger")
            return redirect(url_for('login_page'))
        login_user(user)
        return redirect(url_for('index'))
    return render_template('login.html', form=form)

@app.route('/index')
@login_required
def index():
    return current_user.id

if __name__ == "__main__":
    # db.create_all()
    # u = User(id='param')
    # u.set_password('Param123')
    # db.session.add(u)
    # db.session.commit()

    app.run(debug = True)