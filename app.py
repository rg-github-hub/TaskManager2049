from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_security import Security, UserMixin, RoleMixin, SQLAlchemyUserDatastore, login_required
from flask_security.utils import hash_password

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dfdajfriaejfidfonoi'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:Param123@localhost/png'
app.config['SECURITY_PASSWORD_SALT'] = 'dfdgsdfsadfasg'
db = SQLAlchemy(app)
Bootstrap(app)

roles_users = db.Table('roles_users', db.Column('user_id', db.Integer, db.ForeignKey('user.id')), db.Column('role_id', db.Integer, db.ForeignKey('role.id')))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    email = db.Column(db.String(100), unique = True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean)
    confirmed_at = db.Column(db.DateTime)
    roles = db.relationship('Role', secondary =roles_users, backref = db.backref('users', lazy = 'dynamic'))

class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(40))
    description = db.Column(db.String(255))

user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/abc')
def abc():
    #user_datastore.create_user(email = 'ab@a.com', password = hash_password('abcd'))
    #db.session.commit()
    return "aa"

@app.route('/aa')
@login_required
def aa():
    return 'test'

if __name__ == "__main__":
    app.run(debug=True)


    #flask shell
    # db.create_all()
    # u = User(email='dfdfd.dfdf@sd.com')
    # 
    # db.session.add(u)
    # db.session.commit()


    #Todo 
    # flask security
    # flask blueprint
    #flask sessions
    #flask uploads
    #comment is inserted
    #second comment

