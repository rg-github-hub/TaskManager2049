
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
app = Flask(__name__)
# in mysql
# create database abhaytest  only once
# if you make changes to model delete the tables from mysql and then call db.create_all() again

#for deleting
# use abhay_test;
# drop table table_name;
# note: Order by which you delete the table matters. eg. T2 is dependent on T2 you cannot delete T1 first. You have to
# delete T2 first.

#change the password
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:password@localhost/abhaytest'
db = SQLAlchemy(app)

class T1(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    subject=db.Column(db.String(10))
    marks=db.Column(db.Integer)




class T2(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    test_column = db.Column(db.String(20))
    test_column2 = db.Column (db.String(20))
    
    t1_id=db.Column(db.Integer,db.ForeignKey('t1.id'))
    t1 = db.relationship('T1',backref = db.backref('t2'))

# open terminal in the same directory or directly into vs code terminal
# from test import db, Model1, Model2, ...
# db.create_all()  first time only

# obj=T1(subject="English")
# obj2=T2(test_column = "abc")
# obj.t2.append(obj1)    or     obj2.t1.append(obj)
# db.session.add(obj)
# db.session.add(obj2)
# db.session.commit()
# s = T1.query.filter_by(subject="English", t2 = obj2)

