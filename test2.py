from app import db, User, Role, user_datastore, app
from flask_security.utils import hash_password
with app.app_context():
    u = User.query.filter_by(id=14).first()
    print(u.has_role('Admin'))
    #user_datastore.remove_role_from_user(u, 'Admin')
    #user_datastore.add_role_to_user(u, 'Admin')
    db.session.commit()