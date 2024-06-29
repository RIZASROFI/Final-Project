from flask import Flask, request, jsonify, session
from datetime import datetime
import secrets
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Ganti dengan secret key yang lebih aman

# In-memory storage for users, groups, and logs
users = []
groups = []
logs = []


# Helper function to log activity
def log_activity(action, description):
    logs.append({'timestamp': datetime.utcnow().isoformat(), 'action': action, 'description': description})


# Helper function to find user by username
def find_user_by_username(username):
    return next((user for user in users if user['username'] == username), None)


# Helper function to find user by ID
def find_user_by_id(user_id):
    return next((user for user in users if user['id'] == user_id), None)


# Helper function to find group by ID
def find_group_by_id(group_id):
    return next((group for group in groups if group['id'] == group_id), None)


# CSRF Token generation function
# CSRF Token generation function
def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_urlsafe(16)
    return session['_csrf_token']

# CSRF Token validation function
def check_csrf_token():
    token = request.headers.get('X-CSRF-Token')
    return token and token == session.get('_csrf_token')

# Middleware to set CSRF token in response
@app.after_request
def after_request(response):
    response.headers['X-CSRF-Token'] = generate_csrf_token()
    return response

# Endpoint to get CSRF token
@app.route('/csrf-token', methods=['GET'])
def get_csrf_token():
    token = generate_csrf_token()
    return jsonify({'csrf_token': token}), 200

# Decorator to protect endpoints against CSRF
def csrf_protected(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if request.method != 'POST' and not check_csrf_token():
            return jsonify({'message': 'CSRF token missing or invalid'}), 403
        return func(*args, **kwargs)

    return decorated_function

# Endpoint baru untuk menunjukkan output yang berbeda jika CSRF token tidak valid
@app.route('/protected-endpoint', methods=['POST'])
@csrf_protected
def protected_endpoint():
    return jsonify({'message': 'CSRF token is valid. kamu bisa mengakses endpoint ini.'}), 200

# A. CRUD User
# Endpoint untuk mendaftarkan pengguna baru
@app.route('/users/register', methods=['POST'])
@csrf_protected
def register_user():
    user_data = request.get_json()
    if find_user_by_username(user_data['username']):
        return jsonify({'message': 'Username already exists'}), 400
    user_id = len(users) + 1  # Generate unique user ID
    user_data['id'] = user_id
    user_data['last_active'] = datetime.utcnow().isoformat()
    users.append(user_data)
    log_activity('REGISTER_USER', f"User {user_data['username']} registered.")
    return jsonify({'message': 'User registered successfully', 'user': user_data}), 201


# Endpoint untuk mengambil profil pengguna yang sedang login (Operator)
@app.route('/users/profile', methods=['GET'])
def get_own_profile():
    # Implementasi sebenarnya harus memvalidasi sesi atau token
    operator_id = 1  # Ganti dengan metode yang sesuai untuk mengidentifikasi operator yang sedang login

    # Temukan operator berdasarkan ID atau metode identifikasi yang sesuai
    operator = find_user_by_id(operator_id)
    if operator:
        # Hapus data sensitif seperti password sebelum dikembalikan
        safe_profile = {key: operator[key] for key in operator if key != 'password'}
        return jsonify({'message': 'Operator profile retrieved successfully', 'profile': safe_profile}), 200
    else:
        return jsonify({'message': 'Operator not found'}), 404


# Endpoint untuk mengambil profil pengguna berdasarkan ID (dibatasi hanya untuk admin)
@app.route('/users/<int:user_id>', methods=['GET'])
def get_user_profile(user_id):
    # Implementasi logika untuk membatasi akses ke profil pengguna lain oleh operator
    operator_id = 1  # Ganti dengan metode yang sesuai untuk mengidentifikasi operator yang sedang login

    operator = find_user_by_id(operator_id)
    if not operator:
        return jsonify({'message': 'Operator not found'}), 404

    if operator['id'] != user_id:
        return jsonify({'message': 'You are not authorized to view this profile'}), 403

    user = find_user_by_id(user_id)
    if user:
        safe_profile = {key: user[key] for key in user if key != 'password'}
        return jsonify({'user': safe_profile}), 200
    else:
        return jsonify({'message': 'User not found'}), 404


# Endpoint untuk membuat pengguna baru
@app.route('/users', methods=['POST'])
@csrf_protected
def create_user():
    user_data = request.get_json()
    user_id = len(users) + 1  # Generate unique user ID
    user_data['id'] = user_id
    user_data['last_active'] = datetime.utcnow().isoformat()
    users.append(user_data)
    log_activity('CREATE_USER', f"User {user_data['username']} created.")
    return jsonify({'message': 'User created successfully', 'user': user_data}), 201


# Endpoint untuk mengambil daftar semua pengguna
@app.route('/users', methods=['GET'])
def get_users():
    return jsonify({'users': users}), 200


# Endpoint untuk mengubah informasi pengguna
@app.route('/users/<int:user_id>', methods=['PUT'])
@csrf_protected
def update_user(user_id):
    user_data = request.get_json()
    operator_id = 1  # Ganti dengan metode yang sesuai untuk mengidentifikasi operator yang sedang login

    operator = find_user_by_id(operator_id)
    if not operator:
        return jsonify({'message': 'Operator not found'}), 404

    if operator['id'] != user_id:
        return jsonify({'message': 'You are not authorized to update this user'}), 403

    user = find_user_by_id(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404

    if user_data.get('password'):
        if not user_data.get('old_password') or user_data['old_password'] != user['password']:
            return jsonify({'message': 'Old password is incorrect'}), 400
        user['password'] = user_data['password']

    if user_data.get('fullname'):
        user['fullname'] = user_data['fullname']

    user['last_active'] = datetime.utcnow().isoformat()
    log_activity('UPDATE_USER', f"User {user['username']} updated.")
    return jsonify({'message': 'User updated successfully', 'user': user}), 200


# Endpoint untuk menghapus pengguna
@app.route('/users/<int:user_id>', methods=['DELETE'])
@csrf_protected
def delete_user(user_id):
    user = find_user_by_id(user_id)
    if user:
        users.remove(user)
        log_activity('DELETE_USER', f"User {user['username']} deleted.")
        return jsonify({'message': 'User deleted successfully'}), 200
    return jsonify({'message': 'User not found'}), 404


# B. User Group Management
# Endpoint untuk membuat grup baru
@app.route('/groups', methods=['POST'])
@csrf_protected
def create_group():
    group_data = request.get_json()
    group_data['id'] = len(groups) + 1
    if 'members' in group_data and isinstance(group_data['members'], list):
        members_with_role = []
        for user_id in group_data['members']:
            user = find_user_by_id(user_id)
            if user:
                member_with_role = {"id": user['id'], "username": user['username'], "fullname": user['fullname'],
                                    "role": user['role']}
                members_with_role.append(member_with_role)
        group_data['members'] = members_with_role
    groups.append(group_data)
    log_activity('CREATE_GROUP', f"Group {group_data['name']} created.")
    return jsonify({'message': 'Group created successfully', 'group': group_data}), 201


# Endpoint untuk mengambil daftar semua grup
@app.route('/groups', methods=['GET'])
def get_groups():
    safe_groups = [{'id': group['id'], 'name': group['name']} for group in groups]
    return jsonify({'groups': safe_groups}), 200


# Endpoint untuk mengambil daftar grup tanpa detail anggota
@app.route('/groups/basic', methods=['GET'])
def get_basic_groups():
    safe_groups = [{'id': group['id'], 'name': group['name']} for group in groups]
    return jsonify({'groups': safe_groups}), 200


# Endpoint untuk mengubah informasi grup
@app.route('/groups/<int:group_id>', methods=['PUT'])
@csrf_protected
def update_group(group_id):
    group_data = request.get_json()
    for group in groups:
        if group['id'] == group_id:
            group.update(group_data)
            log_activity('UPDATE_GROUP', f"Group {group['name']} updated.")
            return jsonify({'message': 'Group updated successfully', 'group': group}), 200
    return jsonify({'message': 'Group not found'}), 404


# Endpoint untuk menghapus grup
@app.route('/groups/<int:group_id>', methods=['DELETE'])
@csrf_protected
def delete_group(group_id):
    group = next((group for group in groups if group['id'] == group_id), None)
    if group:
        # Implementasi pengecekan jika operator diperbolehkan menghapus grup tertentu
        operator_id = 1  # Ganti dengan metode yang sesuai untuk mengidentifikasi operator yang sedang login
        operator = find_user_by_id(operator_id)
        if operator:
            # Contoh: Operator hanya boleh menghapus grup jika grup tidak memiliki anggota atau kriteria lain
            if not group.get('members') or len(group['members']) == 0:
                groups.remove(group)
                log_activity('DELETE_GROUP', f"Group {group['name']} deleted by operator {operator['username']}.")
                return jsonify({'message': 'Group deleted successfully'}), 200
            else:
                return jsonify({
                                   'message': 'Cannot delete group with existing members'}), 403  # Atau sesuaikan dengan kriteria Anda
        else:
            return jsonify({'message': 'Operator not found'}), 404
    return jsonify({'message': 'Group not found'}), 404


# Endpoint untuk menambahkan pengguna ke dalam grup
@app.route('/groups/<int:group_id>/users', methods=['POST'])
@csrf_protected
def add_user_to_group(group_id):
    group = next((group for group in groups if group['id'] == group_id), None)
    if not group:
        return jsonify({'message': 'Group not found'}), 404

    group_data = request.get_json()
    user_id = group_data.get('user_id')

    user = find_user_by_id(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404

    if any(member['id'] == user_id for member in group['members']):
        return jsonify({'message': 'User already exists in the group'}), 400

    member_with_role = {
        "id": user['id'],
        "username": user['username'],
        "fullname": user['fullname'],
        "role": user['role']
    }

    if 'members' not in group:
        group['members'] = []

    group['members'].append(member_with_role)
    log_activity('ADD_USER_TO_GROUP', f"User {user['username']} added to group {group['name']}.")
    return jsonify({'message': 'User added to group successfully'}), 200


# Endpoint untuk menghapus pengguna dari grup
@app.route('/groups/<int:group_id>/users', methods=['DELETE'])
@csrf_protected
def remove_user_from_group(group_id):
    group = next((group for group in groups if group['id'] == group_id), None)
    if not group:
        return jsonify({'message': 'Group not found'}), 404

    group_data = request.get_json()
    user_id = group_data.get('user_id')

    user = find_user_by_id(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404

    if not any(member['id'] == user_id for member in group['members']):
        return jsonify({'message': 'User not found in the group'}), 404

    group['members'] = [member for member in group['members'] if member['id'] != user_id]
    log_activity('REMOVE_USER_FROM_GROUP', f"User {user['username']} removed from group {group['name']}.")
    return jsonify({'message': 'User removed from group successfully'}), 200


# C. Activity Logging
# Endpoint untuk memonitor aktivitas pengguna
@app.route('/logs', methods=['GET'])
def monitor_user_actions():
    operator_id = 1  # Ganti dengan metode yang sesuai untuk mengidentifikasi operator yang sedang login

    operator = find_user_by_id(operator_id)
    if operator and operator.get('status') != 'DISABLED':
        return jsonify({'logs': logs}), 200
    else:
        return jsonify({'message': 'Access denied. Operator account is disabled or not authorized to view logs.'}), 403


# D. Security
# Endpoint untuk login
@app.route('/login', methods=['POST'])
@csrf_protected
def login():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'message': 'Invalid request. Please provide both username and password'}), 400

    username = data['username']
    password = data['password']

    user = find_user_by_username(username)
    if not user or user['password'] != password:
        return jsonify({'message': 'Invalid username or password'}), 401

    if user.get('status') == 'DISABLED':
        return jsonify({'message': 'User account is disabled'}), 403

    user['last_active'] = datetime.utcnow().isoformat()
    log_activity('LOGIN', f"User {user['username']} logged in.")
    return jsonify({'message': 'Login successful'}), 200


# Endpoint untuk mengubah password pengguna
@app.route('/users/<int:user_id>/password', methods=['PUT'])
@csrf_protected
def change_password(user_id):
    user_data = request.get_json()
    user = find_user_by_id(user_id)
    if user:
        if 'old_password' in user_data and user_data['old_password'] == user['password']:
            user['password'] = user_data['new_password']
            log_activity('CHANGE_PASSWORD', f"User {user['username']} changed password.")
            return jsonify({'message': 'Password changed successfully'}), 200
        return jsonify({'message': 'Old password is incorrect'}), 400
    return jsonify({'message': 'User not found'}), 404


# Endpoint untuk reset password pengguna lain dengan konfirmasi password administrator
@app.route('/users/<int:user_id>/password/reset', methods=['PUT'])
@csrf_protected
def reset_password_by_admin(user_id):
    admin_data = request.get_json()
    admin_id = 1  # Ganti dengan metode yang sesuai untuk mengidentifikasi administrator yang sedang login

    # Temukan administrator berdasarkan ID atau metode identifikasi yang sesuai
    administrator = find_user_by_id(admin_id)
    if not administrator:
        return jsonify({'message': 'Administrator not found'}), 404

    # Periksa apakah administrator memiliki izin untuk reset password
    # Misalnya, verifikasi apakah administrator adalah admin dengan logika bisnis yang sesuai

    # Dapatkan data pengguna yang akan direset passwordnya
    user = find_user_by_id(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404

    # Periksa apakah administrator telah memasukkan konfirmasi password yang benar
    if 'confirm_password' not in admin_data or admin_data['confirm_password'] != administrator['password']:
        return jsonify({'message': 'Administrator password confirmation failed'}), 403

    # Lakukan reset password
    if 'new_password' in admin_data:
        user['password'] = admin_data['new_password']
        log_activity('RESET_PASSWORD_BY_ADMIN',
                     f"Password for user {user['username']} reset by administrator {administrator['username']}.")
        return jsonify({'message': 'Password reset successfully'}), 200
    else:
        return jsonify({'message': 'New password not provided'}), 400


# Endpoint untuk mengubah kelompok pengguna lain dengan konfirmasi password administrator
@app.route('/users/<int:user_id>/group', methods=['PUT'])
@csrf_protected
def change_user_group_by_admin(user_id):
    admin_data = request.get_json()
    admin_id = 1  # Ganti dengan metode yang sesuai untuk mengidentifikasi administrator yang sedang login

    # Temukan administrator berdasarkan ID atau metode identifikasi yang sesuai
    administrator = find_user_by_id(admin_id)
    if not administrator:
        return jsonify({'message': 'Administrator not found'}), 404

    # Periksa apakah administrator memiliki izin untuk mengubah grup pengguna
    # Misalnya, verifikasi apakah administrator adalah admin dengan logika bisnis yang sesuai

    # Dapatkan data pengguna yang akan diubah grupnya
    user = find_user_by_id(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404

    # Periksa apakah administrator telah memasukkan konfirmasi password yang benar
    if 'confirm_password' not in admin_data or admin_data['confirm_password'] != administrator['password']:
        return jsonify({'message': 'Administrator password confirmation failed'}), 403

    # Lakukan perubahan grup pengguna
    if 'new_group_id' in admin_data:
        new_group_id = admin_data['new_group_id']
        # Implementasi logika untuk mengubah grup pengguna
        # Misalnya, update data pengguna dengan grup baru
        user['group_id'] = new_group_id
        log_activity('CHANGE_USER_GROUP_BY_ADMIN',
                     f"User {user['username']} group changed by administrator {administrator['username']} to group {new_group_id}.")
        return jsonify({'message': 'User group changed successfully'}), 200
    else:
        return jsonify({'message': 'New group ID not provided'}), 400


if __name__ == '__main__':
    app.run(debug=True)
