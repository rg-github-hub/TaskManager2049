from flask import Flask, render_template, flash, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, UserMixin, RoleMixin, SQLAlchemyUserDatastore, login_required, current_user, roles_required
from flask_security.utils import hash_password, verify_password
from flask_mail import Mail,Message
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateField, SelectField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from flask_bootstrap import Bootstrap
app = Flask(__name__)
app.config['SECRET_KEY'] = '^&fdijfoisJIFDJFOI3483&(*&'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:Param123@localhost/png'
app.config['SECURITY_PASSWORD_SALT'] = 'dfdgsdfsadfasg'
# app.config['SECURITY_REGISTERABLE'] = True
# app.config['SECURITY_CONFIRMABLE'] = True
app.config['SECURITY_RECOVERABLE'] = True
db = SQLAlchemy(app)
Bootstrap(app)


app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'param.gupta290999@gmail.com'
app.config['MAIL_PASSWORD'] = 'hfgrpwulyrutrlmo'
app.config['SECURITY_EMAIL_SENDER'] = 'param.gupta290999@gmail.com'
mail = Mail(app)

class Create_user(FlaskForm):
    name=StringField("Name",validators=[DataRequired()])
    email = StringField("Email",validators=[DataRequired(),Email()])
    password=PasswordField("Password",validators=[Length(min=8,max=32),DataRequired()])
    confirm_password=PasswordField("Re-enter Password",validators=[EqualTo('password',message="Passwords do not match, re-enter the password")])
    submit=SubmitField("Create User")

class ShowUser(FlaskForm):
    name=StringField("Name",validators=[DataRequired()])
    email = StringField("Email",validators=[DataRequired(),Email()])
    submit=SubmitField("Update details")

class ChangePassword(FlaskForm):
    password=PasswordField("Password",validators=[Length(min=8,max=32),DataRequired()])
    new_password=PasswordField("New Password",validators=[Length(min=8,max=32),DataRequired()])
    confirm_password=PasswordField("Re-enter Password",validators=[EqualTo('new_password',message="Passwords do not match, re-enter the password")])
    submit=SubmitField("Change Password")
roles_users = db.Table('roles_users', db.Column('user_id', db.Integer, db.ForeignKey('user.id')), db.Column('role_id', db.Integer, db.ForeignKey('role.id')))
assigned_to = db.Table('assigned_to', db.Column('user_id', db.Integer, db.ForeignKey('user.id')), db.Column('project_id', db.Integer, db.ForeignKey('project.id')))
supervises = db.Table('supervises', db.Column('user_id', db.Integer, db.ForeignKey('user.id')), db.Column('project_id', db.Integer, db.ForeignKey('project.id')))



class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    email = db.Column(db.String(100), unique = True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean)
    confirmed_at = db.Column(db.DateTime)
    roles = db.relationship('Role', secondary =roles_users, backref = db.backref('users', lazy = 'dynamic'))
    projects = db.relationship('Project', secondary =assigned_to, backref = db.backref('users', lazy = 'dynamic'))
    projects_supervised = db.relationship('Project', secondary =supervises, backref = db.backref('supervisors', lazy = 'dynamic'))
    #ensure a person can only supervise if they are a superviser role
    #ensure that a superviser must also be assigned to the project

class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(40))
    description = db.Column(db.String(255))

class Project(db.Model):
    id= db.Column(db.Integer,primary_key= True)
    name=db.Column(db.String(40))
    is_done = db.Column(db.Boolean,default = False)
    
    # relationship with user

class Task(db.Model):
    id= db.Column(db.Integer,primary_key= True)
    name=db.Column(db.String(256))
    description=db.Column(db.String(10000))
    is_done = db.Column(db.Boolean, default = False)
    create_date=db.Column(db.DateTime)
    deadline=db.Column(db.DateTime)
    priority=db.Column(db.String(20)) 
    user_id=db.Column(db.Integer,db.ForeignKey('user.id'))
    user = db.relationship('User',backref = db.backref('tasks'))
    project_id=db.Column(db.Integer,db.ForeignKey('project.id'))
    project = db.relationship('Project',backref = db.backref('tasks'))




user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)




@app.route('/')
def home():
    return render_template('test.html', title= "Home")



#jinja2 
@app.route('/create')
@login_required
@roles_required('Admin')
def create():
    pass

@app.route('/create_user', methods=['GET', 'POST'])
def create_user():
    form=Create_user()
    if (form.validate_on_submit()):

        # u = User(name = form.name.data, email=form.email.data, password=hash_password(form.password.data))
        try:
            u = user_datastore.create_user(name = form.name.data, email=form.email.data, password=hash_password(form.password.data))
            db.session.add(u)
            db.session.commit()
        except:
            flash('User could not be created', 'alert-danger')
            return redirect('/create_user')

        flash('User Created', 'alert-success')
        return redirect('/create_user')
    return render_template('create_user.html',form=form)


@app.route('/users')
def users():
    u = User.query.all()
    return render_template('users.html', user_list = u)

@app.route('/users/<id>',methods=['GET', 'POST'])
def user(id):
    u = User.query.filter_by(id=id).first()
    form = ShowUser(name=u.name,email=u.email)
    if (form.validate_on_submit()):
        try:
            u.name=form.name.data
            u.email=form.email.data
            db.session.commit()

        except:
            flash('User details could not be changed', 'alert-danger')
            return redirect(f'/users/{id}')
        flash('Profile Updated', 'alert-success')
        return redirect(f'/users/{id}')
    return render_template('user.html',is_admin=False,form = form)

@app.route("/changepassword",methods=['GET','POST'])
@login_required
def changepassword():
    form=ChangePassword()
    old_pass=current_user.password
    id=current_user.id
    u=User.query.filter_by(id=id).first()

    if (form.validate_on_submit()):
        try:
            if(verify_password(form.password.data,old_pass)):
                u.password=hash_password(form.new_password.data)
                db.session.commit() 
                flash('Password is changed', 'alert-success')
            else:
                flash('Incorrect Password Entered', 'alert-danger')
                return redirect('/changepassword')
        except:
            flash('Password could not be changed', 'alert-danger')
            return redirect(f'/users/{id}')

    return render_template('change_password.html',form=form)

@login_required
@app.route("/delete_user",methods=["POST"])
def test():
    try:
        id=int(request.json['id'])
        if(id == current_user.id):
            flash('User can not be deleted', 'alert-danger')
            return "not_deleted"
        u=User.query.filter_by(id=id).first()
        db.session.delete(u)
        db.session.commit()
    except:
        flash('User was not deleted', 'alert-danger')
        return "not deleted"
    flash('User deleted successfully','alert-success')
    return "deleted"


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
    #flask mail
    #flask celery

#User, Role, Project, Task

#Admin - (Create account), create projects, assign people to a project, (edit user), edit project, (delete user) or project, task manages all projects. 
#my projects
#routes require only admin: create_user,users, delete_user, 
#flag variable for individual users page

# (page that lists all users. only accessible by admin. This will open the edit user page.)

# u = User.query.filter_by(id=1).first()
# u.name = "abc"
# u.email = "df.l@hj.com"
# db.session.commit()