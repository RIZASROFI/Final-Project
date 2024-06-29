from datetime import datetime
from flask import Flask, request, jsonify
from flask_login import LoginManager, UserMixin, login_required, current_user
from flask_principal import Principal, Permission, identity_loaded, UserNeed, RoleNeed
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user_management.db'
db = SQLAlchemy(app)

# Initialize Flask-Login and Flask-Principal
login_manager = LoginManager(app)
principals = Principal(app)

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    fullname = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    status = db.Column(db.String(10), nullable=False, default='ACTIVE')
    created_time = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    role = db.Column(db.String(50), nullable=False, default='OPERATOR')
    groups = db.relationship('Group', secondary='user_group_membership', back_populates='users')

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    users = db.relationship('User', secondary='user_group_membership', back_populates='groups')

class UserGroupMembership(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    user = db.relationship(User, backref=db.backref('membership', cascade='all, delete-orphan'))
    group = db.relationship(Group, backref=db.backref('membership', cascade='all, delete-orphan'))

class UserActionLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship(User, backref=db.backref('action_logs', cascade='all, delete-orphan'))

# Create the database and tables
with app.app_context():
    db.create_all()

# Utility functions
def log_action(user_id, action):
    log = UserActionLog(user_id=user_id, action=action)
    db.session.add(log)
    db.session.commit()

# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Flask-Principal identity loaded callback
@identity_loaded.connect_via(app)
def on_identity_loaded(sender, identity):
    identity.user = current_user
    if hasattr(current_user, 'id'):
        identity.provides.add(UserNeed(current_user.id))
    if hasattr(current_user, 'role'):
        identity.provides.add(RoleNeed(current_user.role))

# Define permissions
admin_permission = Permission(RoleNeed('ADMIN'))

# Register User
@app.route('/register', methods=['POST'])
@login_required
@admin_permission.require(http_exception=403)
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    fullname = data.get('fullname')
    email = data.get('email')

    if not username or not password or not fullname or not email:
        return jsonify({'message': 'All fields are required'}), 400

    existing_user = User.query.filter((User.username == username) | (User.email == email)).first()

    if existing_user:
        return jsonify({'message': 'Username or email already exists'}), 400

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = User(username=username, password=hashed_password, fullname=fullname, email=email)
    db.session.add(new_user)
    db.session.commit()
    log_action(new_user.id, 'Registered user')

    return jsonify({'message': 'User registered successfully'}), 201

# User CRUD
@app.route('/users', methods=['POST'])
@login_required
@admin_permission.require(http_exception=403)
def create_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    fullname = data.get('fullname')
    email = data.get('email')

    if not username or not password or not fullname or not email:
        return jsonify({'message': 'All fields are required'}), 400

    existing_user = User.query.filter((User.username == username) | (User.email == email)).first()

    if existing_user:
        return jsonify({'message': 'Username or email already exists'}), 400

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = User(username=username, password=hashed_password, fullname=fullname, email=email)
    db.session.add(new_user)
    db.session.commit()
    log_action(new_user.id, 'Created user')

    return jsonify({'message': 'User created successfully'}), 201

@app.route('/users', methods=['GET'])
@login_required
@admin_permission.require(http_exception=403)
def read_users():
    users = User.query.all()
    return jsonify([{'id': user.id, 'username': user.username, 'fullname': user.fullname, 'email': user.email, 'status': user.status, 'created_time': user.created_time, 'last_login': user.last_login} for user in users])

@app.route('/users/<int:user_id>', methods=['PUT'])
@login_required
@admin_permission.require(http_exception=403)
def update_user(user_id):
    data = request.json
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404
    if 'username' in data:
        user.username = data['username']
    if 'fullname' in data:
        user.fullname = data['fullname']
    if 'email' in data:
        user.email = data['email']
    if 'password' in data:
        user.password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    if 'status' in data:
        user.status = data['status']
    db.session.commit()
    log_action(user_id, 'Updated user')
    return jsonify({'message': 'User updated successfully'})

@app.route('/users/<int:user_id>', methods=['DELETE'])
@login_required
@admin_permission.require(http_exception=403)
def delete_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404
    db.session.delete(user)
    db.session.commit()
    log_action(user_id, 'Deleted user')
    return jsonify({'message': 'User deleted successfully'})

@app.route('/users/search', methods=['GET'])
@login_required
@admin_permission.require(http_exception=403)
def search_users():
    query = request.args.get('q')
    users = User.query.filter((User.username.like(f'%{query}%')) | (User.fullname.like(f'%{query}%'))).all()
    return jsonify([{'id': user.id, 'username': user.username, 'fullname': user.fullname, 'email': user.email, 'status': user.status, 'created_time': user.created_time, 'last_login': user.last_login} for user in users])

# User Group CRUD
@app.route('/groups', methods=['POST'])
@login_required
@admin_permission.require(http_exception=403)
def create_group():
    data = request.json
    new_group = Group(name=data['name'])
    db.session.add(new_group)
    db.session.commit()
    return jsonify({'message': 'Group created successfully'}), 201

@app.route('/groups', methods=['GET'])
@login_required
@admin_permission.require(http_exception=403)
def read_groups():
    groups = Group.query.all()
    return jsonify([{'id': group.id, 'name': group.name} for group in groups])

@app.route('/groups/<int:group_id>', methods=['PUT'])
@login_required
@admin_permission.require(http_exception=403)
def update_group(group_id):
    data = request.json
    group = Group.query.get(group_id)
    if not group:
        return jsonify({'message': 'Group not found'}), 404
    group.name = data['name']
    db.session.commit()
    return jsonify({'message': 'Group updated successfully'})

@app.route('/groups/<int:group_id>', methods=['DELETE'])
@login_required
@admin_permission.require(http_exception=403)
def delete_group(group_id):
    group = Group.query.get(group_id)
    if not group:
        return jsonify({'message': 'Group not found'}), 404
    db.session.delete(group)
    db.session.commit()
    return jsonify({'message': 'Group deleted successfully'})

# Manage Users in Groups
@app.route('/groups/<int:group_id>/users/<int:user_id>', methods=['POST'])
@login_required
@admin_permission.require(http_exception=403)
def add_user_to_group(group_id, user_id):
    group = Group.query.get(group_id)
    user = User.query.get(user_id)
    if not group or not user:
        return jsonify({'message': 'Group or User not found'}), 404
    group.users.append(user)
    db.session.commit()
    return jsonify({'message': 'User added to group successfully'})

@app.route('/groups/<int:group_id>/users/<int:user_id>', methods=['DELETE'])
@login_required
@admin_permission.require(http_exception=403)
def remove_user_from_group(group_id, user_id):
    membership = UserGroupMembership.query.filter_by(group_id=group_id, user_id=user_id).first()
    if not membership:
        return jsonify({'message': 'User not in group'}), 404
    db.session.delete(membership)
    db.session.commit()
    return jsonify({'message': 'User removed from group successfully'})

# Activity Logging
@app.route('/logs', methods=['GET'])
@login_required
@admin_permission.require(http_exception=403)
def read_logs():
    logs = UserActionLog.query.all()
    return jsonify([{'id': log.id, 'action': log.action, 'user_id': log.user_id, 'timestamp': log.timestamp} for log in logs])

if __name__ == '__main__':
    app.run(debug=True)
