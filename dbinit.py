from app import db, User, Role, user_datastore, app
from flask_security.utils import hash_password
with app.app_context():

    db.create_all()
    r=user_datastore.create_role(name="Admin")
    u = user_datastore.create_user(name = "admin", email="abhay.aggarwal99@gmail.com", password=hash_password("admin"), roles = ['Admin'])
    db.session.add(u)
    db.session.add(r)
    db.session.commit()

