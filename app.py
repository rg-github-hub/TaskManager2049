from flask import Flask, render_template, flash, redirect, request, request
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, UserMixin, RoleMixin, SQLAlchemyUserDatastore, login_required, current_user, roles_required
from flask_security.utils import hash_password, verify_password
from flask_mail import Mail,Message
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateField, SelectField
from wtforms.validators import DataRequired, Email, Length, EqualTo

from wtforms.widgets import TextArea

app = Flask(__name__)
app.config['SECRET_KEY'] = '^&fdijfoisJIFDJFOI3483&(*&'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:abhay1234@localhost/png'
app.config['SECURITY_PASSWORD_SALT'] = 'dfdgsdfsadfasg'
# app.config['SECURITY_REGISTERABLE'] = True
# app.config['SECURITY_CONFIRMABLE'] = True
app.config['SECURITY_RECOVERABLE'] = True
db = SQLAlchemy(app)



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
    name=StringField("Name",validators=[Length(max=50),DataRequired()])
    email = StringField("Email",validators=[Length(max=100),DataRequired(),Email()])
    submit=SubmitField("Update details")

class ChangePassword(FlaskForm):
    password=PasswordField("Password",validators=[Length(min=8,max=32),DataRequired()])
    new_password=PasswordField("New Password",validators=[Length(min=8,max=32),DataRequired()])
    confirm_password=PasswordField("Re-enter Password",validators=[EqualTo('new_password',message="Passwords do not match, re-enter the password")])
    submit=SubmitField("Change Password")

class Create_Project(FlaskForm):
    name=StringField("Name",validators=[Length(max=40),DataRequired()])
    description=StringField("Description",validators=[Length(max=255)],widget=TextArea())
    submit=SubmitField("Create Project")

class Show_Project(FlaskForm):
    name=StringField("Name",validators=[Length(max=40),DataRequired()])
    description=StringField("Description",validators=[Length(max=255)],widget=TextArea())
    submit=SubmitField("Update Project")

class Assign_user(FlaskForm):
    user=SelectField("User Name")
    submit=SubmitField("Add")

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
    description = db.Column(db.String(255))
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
@login_required
@roles_required('Admin')
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
@login_required
@roles_required('Admin')

def users():
    u = User.query.all()
    return render_template('users.html', user_list = u)

@app.route('/users/<id>',methods=['GET', 'POST'])
@login_required
def user(id):
    is_admin=current_user.has_role("Admin")
    if (not is_admin) and current_user.id != int(id):
        flash('Accessing other user profile not allowed', 'alert-danger')
        return redirect('/')
    u = User.query.filter_by(id=id).first()
    is_profile_admin=u.has_role("Admin")
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
    return render_template('user.html',is_admin=is_admin, is_profile_admin = is_profile_admin,form = form,id=id)

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


@app.route("/delete_user",methods=["POST"])
@login_required
@roles_required('Admin')
def delete_user():
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


@app.route("/create_project",methods=["GET","POST"])
@login_required
@roles_required('Admin')
def create_project():
    form=Create_Project()
   
    if (form.validate_on_submit()):
        try:
            p=Project(name=form.name.data,description=form.description.data)
            db.session.add(p)
            db.session.commit()

        except Exception as e:
            print(e)
            flash('Project could not be created', 'alert-danger')
            return redirect('/create_project')
        flash('Project Created', 'alert-success')
        return redirect('/create_project')
    

    return render_template("create_project.html",form=form)

@app.route('/projects')
@login_required
def projects():
    p = Project.query.all()
    return render_template('projects.html', project_list=p,is_admin=True)

@app.route('/projects/<id>',methods=['GET', 'POST'])
@login_required
def project(id):
    p = Project.query.filter_by(id=id).first()
    all_users=User.query.all()
    user_assigned=p.users
    supervisors=p.supervisors
    user_assigned=[i for i in  user_assigned if i not in supervisors]
    choices=[]
    for user in all_users:
        if user not in user_assigned:
            l=[]
            l.append(user.id)
            l.append(f'{user.name} ({user.id})')
            choices.append(l)
    form = Show_Project(name=p.name,description=p.description)
    form1 = Assign_user() 
    form1.user.choices=choices
    

    if (form.validate_on_submit() and request.form['form-name'] == 'form'):
        try:
            p.name=form.name.data
            p.description=form.description.data
            db.session.commit()
        except:
            flash('Project details could not be changed', 'alert-danger')
            return redirect(f'/projects/{id}')
        flash('Project Updated', 'alert-success')
        return redirect(f'/projects/{id}')
    if(form1.is_submitted() and request.form['form-name'] == 'form1'):
        try:
            user_id=int(form1.user.data)
            u=User.query.filter_by(id=user_id).first()
            p.users.append(u)
            db.session.commit()
            flash('User was added to this project', 'alert-success') 
            
        except Exception as e:
            print(e)
            flash('User was not added to the project','alert-danger')
        return redirect(f'/projects/{id}')       
    return render_template('project.html',is_admin=current_user.has_role('Admin'),form = form,form1=form1,user_assigned=user_assigned,id=id,supervisors=supervisors)




@app.route("/delete_project",methods=["POST"])
@roles_required('Admin')
def delete_project():
    try:
        id=int(request.json['id'])
        p=Project.query.filter_by(id=id).first()
        db.session.delete(p)
        db.session.commit()
    except Exception as e:
        print(e)
        flash('Project was not deleted', 'alert-danger')
        return "not deleted"
    flash('Project deleted successfully','alert-success')
    return "deleted"

@app.route("/make_admin/<id>")
@login_required
@roles_required('Admin')
def make_admin(id):
    try:
        u=User.query.filter_by(id=id).first()
        user_datastore.add_role_to_user(u, 'Admin')
        db.session.commit()
        flash('User was made admin','alert-success')
    except:
        flash('User was not be made admin','alert-danger')
    
    return redirect(f'/users/{id}')

@app.route("/remove_admin/<id>")
@login_required
@roles_required('Admin')
def remove_admin(id):
    if current_user.id == int(id):
        flash('Can not be removed as an admin','alert-danger')
        return redirect(f'/users/{id}')
    try:
        u=User.query.filter_by(id=id).first()
        user_datastore.remove_role_from_user(u, 'Admin')
        db.session.commit()
        flash('User was removed as admin','alert-success')
    except:
        flash('Can not be removed as an admin','alert-danger')
    return redirect(f'/users/{id}')

@app.route("/make_manager/<user_id>/<project_id>")
def make_manager(user_id,project_id):
    try:
        p=Project.query.filter_by(id=project_id).first()
        u=User.query.filter_by(id=user_id).first()
        p.supervisors.append(u)
        db.session.commit()
        flash('User was made manager','alert-success')
    except Exception as e:
        print(e)
        flash('User was not made manager','alert-danger')
    return redirect(f'/projects/{project_id}')

@app.route("/remove_manager/<user_id>/<project_id>")
def remove_manager(user_id,project_id):
    try:
        p=Project.query.filter_by(id=project_id).first()
        u=User.query.filter_by(id=user_id).first()
        p.supervisors.remove(u)
        db.session.commit()
        flash('User was made assignee','alert-success')
    except Exception as e:
        print(e)
        flash('User was not made assignee','alert-danger')
    return redirect(f'/projects/{project_id}')

@app.route("/remove_assignee/<user_id>/<project_id>")
def remove_assignee(user_id,project_id):
    try:
        p=Project.query.filter_by(id=project_id).first()
        u=User.query.filter_by(id=user_id).first()
        p.users.remove(u)
        db.session.commit()
        flash('User was removed from project','alert-success')
    except Exception as e:
        print(e)
        flash('User was not removed from project','alert-danger')
    return redirect(f'/projects/{project_id}')



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

#Admin - (Create account), (create projects), (assign people to a project), (edit user), (edit project), (delete user) or (project), task manages all projects. 
#my projects
#routes require only admin: create_user,users, delete_user, 
#flag variable for individual users page


# u = User.query.filter_by(id=1).first()
# u.name = "abc"
# u.email = "df.l@hj.com"
# db.session.commit()


#in project page check if the person is manager and only show button to appropriate manager and admins, also add restrictions to the path
#fix catogery of default message