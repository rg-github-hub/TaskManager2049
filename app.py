from flask import Flask, render_template, flash, redirect, request, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, UserMixin, RoleMixin, SQLAlchemyUserDatastore, login_required, current_user, roles_required
from flask_security.utils import hash_password, verify_password
from flask_mail import Mail,Message
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateField, SelectField,RadioField, BooleanField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Optional
from wtforms.fields.html5 import DateField, DateTimeField, DateTimeLocalField, TimeField
from datetime import datetime,date
import uuid 

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
app.config['MAIL_USERNAME'] = 'aggarwal.abhay1999@gmail.com'
app.config['MAIL_PASSWORD'] = 'czxxzbydawemifjv'
app.config['SECURITY_EMAIL_SENDER'] = 'aggarwal.abhay1999@gmail.com'
mail = Mail(app)



class Create_user(FlaskForm):
    name=StringField("Name",validators=[DataRequired()])
    email = StringField("Email",validators=[DataRequired(),Email()])
    password=PasswordField("Password",validators=[Length(min=6,max=32),DataRequired()])
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
    user=StringField("User Name")
    submit=SubmitField("Add")

class Create_task(FlaskForm):
    name=StringField("Task Name",validators=[Length(max=256),DataRequired()])
    description=StringField("Description",validators=[Optional()],widget=TextArea())
    priority=RadioField("Priority",choices=[["0"," Low"],["1"," Medium"],["2"," High"]])
    start_date=DateTimeField("Start Date",validators=[Optional()],format='%d-%m-%Y %I:%M %p')
    deadline=DateTimeField("Deadline",validators=[Optional()],format='%d-%m-%Y %I:%M %p')
    add_user=SelectField("Assigning to User",validators=[DataRequired()])
    submit=SubmitField("Add Task")

class Edit_task(FlaskForm):
    name=StringField("Task Name",validators=[Length(max=256),DataRequired()])
    description=StringField("Description",validators=[Optional()],widget=TextArea())
    priority=RadioField("Priority", choices=[["0"," Low"],["1"," Medium"],["2"," High"]],validators=[DataRequired()])
    start_date=DateTimeField("Start Date",validators=[Optional()],format='%d-%m-%Y %I:%M %p')
    deadline=DateTimeField("Deadline",validators=[DataRequired()],format='%d-%m-%Y %I:%M %p')
    is_done=BooleanField("Mark as done")
    submit=SubmitField("Update Task")

# class Add_task(FlaskForm):
#     name=StringField("Task Name",validators=[Length(max=256),DataRequired()])
#     time=TimeField("Deadline",validators=[DataRequired()],format='%H:%M')
#     submit=SubmitField("Add Task")


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
    description=db.Column(db.Text)
    is_done = db.Column(db.Boolean, default = False)
    create_date=db.Column(db.DateTime)
    start_date=db.Column(db.DateTime)
    deadline=db.Column(db.DateTime)
    priority=db.Column(db.Integer) 
    user_id=db.Column(db.Integer,db.ForeignKey('user.id'))
    user = db.relationship('User',backref = db.backref('tasks'),foreign_keys=user_id)
    project_id=db.Column(db.Integer,db.ForeignKey('project.id'))
    project = db.relationship('Project',backref = db.backref('tasks'))
    created_by_id=db.Column(db.Integer,db.ForeignKey('user.id'))
    created_by = db.relationship('User',backref = db.backref('tasks_created'),foreign_keys=created_by_id)


class MyTask(db.Model):
    id= db.Column(db.Integer,primary_key= True)
    title=db.Column(db.String(256))
    start=db.Column(db.String(256))
    end=db.Column(db.String(256))
    backgroundColor=db.Column(db.String(256))
    user_id=db.Column(db.Integer,db.ForeignKey('user.id'))
    user = db.relationship('User',backref = db.backref('my_tasks'),foreign_keys=user_id)

user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)




@app.route('/')
@login_required
def home():
    num_projects=len(current_user.projects)
    num_tasks=len(current_user.tasks)
    today_tasks=0
    week_tasks=0
    for i in current_user.tasks:
        if i.deadline and i.deadline.date()== date.today():
            today_tasks+=1
        if i.deadline:
            d1 = i.deadline
            d2 = datetime.today()
            if d1.isocalendar()[1] == d2.isocalendar()[1] and d1.year == d2.year:
                week_tasks+=1

    return render_template('home.html', title= "Dashboard", tasks=current_user.tasks, datetime=datetime, num_projects=num_projects, num_tasks=num_tasks, today_tasks=today_tasks, week_tasks=week_tasks)



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
        try:
            u = user_datastore.create_user(name = form.name.data, email=form.email.data, password=hash_password(form.password.data))
            db.session.add(u)    
            db.session.commit()
        except :
            flash('User could not be created', 'error')
            return redirect('/create_user')
        flash('User Created', 'success')
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
        flash('Accessing other user profile not allowed', 'error')
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
            flash('User details could not be changed', 'error')
            return redirect(f'/users/{id}')
        flash('Profile Updated', 'success')
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
                flash('Password is changed', 'success')
            else:
                flash('Incorrect Password Entered', 'error')
                return redirect('/changepassword')
        except:
            flash('Password could not be changed', 'error')
            return redirect(f'/users/{id}')

    return render_template('change_password.html',form=form)


@app.route("/delete_user",methods=["POST"])
@login_required
@roles_required('Admin')
def delete_user():
    try:
        id=int(request.json['id'])
        if(id == current_user.id):
            flash('User can not be deleted', 'error')
            return "not_deleted"
        u=User.query.filter_by(id=id).first()
        db.session.delete(u)
        db.session.commit()
    except Exception as e:
        print(e)
        flash('User was not deleted', 'error')
        return "not deleted"
    flash('User deleted successfully','success')
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
            flash('Project could not be created', 'error')
            return redirect('/create_project')
        flash('Project Created', 'success')
        return redirect('/create_project')
    return render_template("create_project.html",form=form)

@app.route('/projects')
@login_required
def projects():
    is_admin=current_user.has_role('Admin')
    p = Project.query.all() if is_admin else current_user.projects
    return render_template('projects.html', project_list=p,is_admin=is_admin)

@app.route('/projects/<id>',methods=['GET', 'POST'])
@login_required
def project(id):
    p = Project.query.filter_by(id=id).first()
    user_assigned=p.users
    supervisors=p.supervisors
    user_assigned=[i for i in  user_assigned if i not in supervisors]
    form = Show_Project(name=p.name,description=p.description)
    form1 = Assign_user() 
    is_admin=current_user.has_role('Admin')
    task_list=[]
    is_manager=True if current_user in supervisors else False
    for i in p.tasks:
        if i.user_id==current_user.id or i.created_by_id==current_user.id:
            task_list.append(i)
    if (form.validate_on_submit() and request.form['form-name'] == 'form' and is_admin):
        try:
            p.name=form.name.data
            p.description=form.description.data
            db.session.commit()
        except:
            flash('Project details could not be changed', 'error')
            return redirect(f'/projects/{id}')
        flash('Project Updated', 'success')
        return redirect(f'/projects/{id}')
        
    if(form1.is_submitted() and request.form['form-name'] == 'form1' and (is_admin or is_manager)):
        try:
            user_mail=form1.user.data
            u=User.query.filter_by(email=user_mail).first()
            if u:
                if u in p.users:
                    flash('User already in project','error')
                else:
                    p.users.append(u)
                    db.session.commit()
                    flash('User was added to this project', 'success')
            else:
                flash('Entered User does not exist','error')
        except Exception as e:
            print(e)
            flash('User was not added to the project','error')
        return redirect(f'/projects/{id}')       
    return render_template('project.html',is_admin=is_admin,is_manager=is_manager,form = form,form1=form1,user_assigned=user_assigned,id=id,supervisors=supervisors, tasks=task_list, datetime=datetime)


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
        flash('Project was not deleted', 'error')
        return "not deleted"
    flash('Project deleted successfully','success')
    return "deleted"

@app.route("/make_admin/<id>")
@login_required
@roles_required('Admin')
def make_admin(id):
    try:
        u=User.query.filter_by(id=id).first()
        user_datastore.add_role_to_user(u, 'Admin')
        db.session.commit()
        flash('User was made admin','success')
    except:
        flash('User was not be made admin','error')
    
    return redirect(f'/users/{id}')

@app.route("/remove_admin/<id>")
@login_required
@roles_required('Admin')
def remove_admin(id):
    if current_user.id == int(id):
        flash('Can not be removed as an admin','error')
        return redirect(f'/users/{id}')
    try:
        u=User.query.filter_by(id=id).first()
        user_datastore.remove_role_from_user(u, 'Admin')
        db.session.commit()
        flash('User was removed as admin','success')
    except:
        flash('Can not be removed as an admin','error')
    return redirect(f'/users/{id}')

@app.route("/make_manager/<user_id>/<project_id>")
@login_required
@roles_required('Admin')
def make_manager(user_id,project_id):
    try:
        p=Project.query.filter_by(id=project_id).first()
        u=User.query.filter_by(id=user_id).first()
        p.supervisors.append(u)
        db.session.commit()
        flash('User was made manager','success')
    except Exception as e:
        print(e)
        flash('User was not made manager','error')
    return redirect(f'/projects/{project_id}')

@app.route("/remove_manager/<user_id>/<project_id>")
@login_required
@roles_required('Admin')
def remove_manager(user_id,project_id):
    try:
        p=Project.query.filter_by(id=project_id).first()
        u=User.query.filter_by(id=user_id).first()
        p.supervisors.remove(u)
        db.session.commit()
        flash('User was made assignee','success')
    except Exception as e:
        print(e)
        flash('User was not made assignee','error')
    return redirect(f'/projects/{project_id}')

@app.route("/remove_assignee/<user_id>/<project_id>")
@login_required
def remove_assignee(user_id,project_id):
    p=Project.query.filter_by(id=project_id).first()
    is_admin=current_user.has_role('Admin')
    is_manager=True if current_user in p.supervisors else False
    if is_admin or is_manager:
        try:
            u=User.query.filter_by(id=user_id).first()
            p.users.remove(u)
            db.session.commit()
            flash('User was removed from project','success')
        except Exception as e:
            print(e)
            flash('User was not removed from project','error')
    return redirect(f'/projects/{project_id}')

@app.route("/create_task/<project_id>",methods=["POST","GET"])
@login_required
def create_task(project_id):
    p=Project.query.filter_by(id=project_id).first()
    is_admin=current_user.has_role('Admin')
    is_manager=True if current_user in p.supervisors else False
    
    if not (is_admin or is_manager):
        return redirect(f'/projects/{project_id}')
    form=Create_task()
    choices=[]
    for user in p.users:
        if user.id != current_user.id:
            l=[]
            l.append(str(user.id))
            l.append(f'{user.name} ({user.id})')
            choices.append(l)
    form.add_user.choices=choices
    if form.validate_on_submit():
        if form.start_date.data and form.deadline.data:
            if form.start_date.data>form.deadline.data:
                return redirect(f'/projects/{project_id}')
        try:
            u=User.query.filter_by(id=form.add_user.data).first()
            t=Task(name=form.name.data,priority=form.priority.data,project=p,user=u,create_date=datetime.now(),created_by=current_user)
            if form.deadline.data:
                t.deadline=form.deadline.data
            if form.start_date.data:
                t.start_date=form.start_date.data
            file_name="files/description_id"+str(uuid.uuid1())
            t.description=file_name
            with open(file_name,"w") as file_object:
                file_object.write(form.description.data)
            db.session.add(t)
            db.session.commit()
            flash("Task was created","success")
        except Exception as e:
            print(e)
            flash("Task was not created","error")
        return redirect(f'/projects/{project_id}')
    return render_template("create_task.html",form=form)
    
class Testform(FlaskForm):
    description=StringField("Description",validators=[Optional()],widget=TextArea())
    submit=SubmitField()



    
@app.route("/edit_task/<task_id>",methods=["POST","GET"])
@login_required
def edit_task(task_id):
    form=Edit_task()
    t=Task.query.filter_by(id=task_id).first()
    if current_user!=t.created_by:
        return redirect('/')
    if form.validate_on_submit():
        try:
            t.name=form.name.data
            t.priority=form.priority.data
            t.start_date=form.start_date.data
            t.deadline=form.deadline.data
            t.is_done=form.is_done.data
            db.session.commit()
            print("Inside validation")
            with open(t.description,"w") as file_object:
                file_object.write(form.description.data)
            flash('The task is updated','success')
        except:
            flash('The task is not updated','error')
        return redirect(f'/edit_task/{task_id}')
    low=""
    medium=""
    high=""
    if(t.priority==0):
        low="checked"
    elif t.priority==1:
        medium="checked"
    else:
        high="checked"
    form.name.data=t.name
    form.start_date.data=t.start_date
    form.deadline.data=t.deadline
    file_name=t.description
    form.is_done.data=t.is_done
    with open(file_name) as f:
        form.description.data=f.read()
    
    return render_template('edit_task.html',form=form, low_checked=low, medium_checked=medium, high_checked=high,assigned_to=t.user.name)


@app.route("/view_task/<task_id>")
@login_required
def view_task(task_id):
    t=Task.query.filter_by(id=task_id).first()
    if current_user.id != t.user_id:
        return redirect('/')
    description=""
    with open(t.description) as f:
        description=f.read()
    return render_template('view_task.html',t=t,description=description, datetime=datetime)

@app.route("/delete_task/<task_id>",methods=["GET"])
@login_required
def delete_task(task_id):
    t=Task.query.filter_by(id=task_id).first()
    if current_user.id != t.created_by_id:
        return redirect('/')
    try:
        db.session.delete(t)
        db.session.commit()
        flash("Task is deleted",'success')
    except Exception as e:
        print(e)
        flash("Task is not deleted",'error')
    return redirect(f'/projects/{t.project_id}')

# @app.route("/calendar",methods=["GET","POST"])
# @login_required
# def calendar():
#     t=Task.query.filter_by(user_id=current_user.id)
#     return render_template("calendar.html", tasks=t)

@app.route("/calendar",methods=["GET","POST"])
@login_required
def test_calendar():
    t=Task.query.filter_by(user_id=current_user.id)
    t1=MyTask.query.filter_by(user_id=current_user.id)
    return render_template("test_calendar.html", tasks=t,saved_tasks=t1)

# @app.route("/calendar_test",methods=["GET","POST"])

# def calendar_test():
#     t=MyTask.query.filter_by(user_id=current_user.id)
#     form=Add_task()
#     return render_template("calendar_test.html", my_tasks=t, form=form)


@app.route("/save_mytask",methods=["POST"])
def save_mytask():
    r=request.json
    try:
        MyTask.query.filter_by(user_id=current_user.id).delete()
        for i in r:

            t=MyTask(start=i["start"],end=i["end"],backgroundColor=i["backgroundColor"],title=i["title"],user_id=current_user.id)
            db.session.add(t)
        db.session.commit()

    except Exception as e:
        print(e)
        db.session.rollback()
        return abort(500)

    print(r)
    return "abc"

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



# u = User.query.filter_by(id=1).first()
# u.name = "abc"
# u.email = "df.l@hj.com"
# db.session.commit()





##DASHBOARD IDEAS
#dashboard would be profile page
#List of project
#Notifications

## FEATURES TO BE ADDED
#Board view for each project with all tasks
#Multiple folders
#Each list should have board view
#Calendar synchronization
#chats
# task column in column sizes
#Task reporting and submission
#dashboard icons in phone view
#users make for smaller screen size
# add search column for users

##CURRENT TO-DO










#THINGS TO TAKE CARE OF WHIE USING IT IN OTHER DEVICES:
#>>pip3 install -U Werkzeug==0.16.0