from flask import Flask, render_template, request, redirect, url_for, flash, session
from functools import wraps
import os
from flask import jsonify
from utils import generate_random_password
from utils import (
    generate_salt, hash_password, save_master_password, save_url_to_monitor, encrypt_data, save_passwords,
    verify_master_password, save_password_entry, get_stored_passwords, check_password_pwned, delete_url_from_monitor
)
from config import Config
from datetime import datetime, timedelta

app = Flask(__name__)
app.config.from_object(Config)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'authenticated' not in session:
            return redirect(url_for('login'))
            
        # Check if session has expired
        if 'last_activity' in session:
            last_activity = datetime.fromisoformat(session['last_activity'])
            if datetime.now() - last_activity > timedelta(seconds=Config.SESSION_TIMEOUT):
                session.clear()
                flash('Session expired. Please login again.', 'error')
                return redirect(url_for('login'))
                
        # Update last activity timestamp
        session['last_activity'] = datetime.now().isoformat()
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form.get('password')
        
        if verify_master_password(password):
            session['authenticated'] = True
            session['master_password'] = password
            session['last_activity'] = datetime.now().isoformat()  # Add this line
            return redirect(url_for('dashboard'))
        flash('Invalid password', 'error')
    
    needs_setup = not os.path.exists(Config.MASTER_PASSWORD_FILE)
    return render_template('login.html', needs_setup=needs_setup)

@app.route('/setup', methods=['POST'])
def setup():
    if os.path.exists(Config.MASTER_PASSWORD_FILE):
        flash('Setup already completed', 'error')
        return redirect(url_for('login'))
        
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    
    if password != confirm_password:
        flash('Passwords do not match', 'error')
        return redirect(url_for('login'))
        
    salt = generate_salt()
    save_master_password(password, salt)
    
    flash('Master password created successfully', 'success')
    return redirect(url_for('login'))

@app.route('/add_password', methods=['GET', 'POST'])
@login_required
def add_password():
    if request.method == 'GET':
        return render_template('add_password.html')
    
    master_password = session.get('master_password')
    if not master_password:
        flash('Session expired. Please login again.', 'error')
        return redirect(url_for('login'))

    data = {
        'title': request.form.get('title'),
        'username': request.form.get('username'),
        'password': request.form.get('password'),
        'url': request.form.get('url'),
        'notes': request.form.get('notes')
    }

    # Save URL for monitoring
    save_url_to_monitor(data['url'])

    # Use consistent salt
    save_password_entry(data['title'], data, master_password, b'initial_salt')
    flash('Password added successfully', 'success')
    return redirect(url_for('dashboard'))

@app.route('/edit_password/<title>', methods=['GET', 'POST'])
@login_required
def edit_password(title):
    master_password = session.get('master_password')
    if not master_password:
        flash('Session expired. Please login again.', 'error')
        return redirect(url_for('login'))

    salt = b'initial_salt'  # Consistent salt for retrieval
    stored_passwords = get_stored_passwords(master_password, salt)
    password_data = next((p for p in stored_passwords if p['title'] == title), None)

    if not password_data:
        flash('Password entry not found', 'error')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        updated_data = {
            'title': request.form.get('title'),
            'username': request.form.get('username'),
            'password': request.form.get('password'),
            'url': request.form.get('url'),
            'notes': request.form.get('notes')
        }

        # Substitua a senha existente na lista
        for idx, entry in enumerate(stored_passwords):
            if entry['title'] == title:
                stored_passwords[idx] = updated_data  # Atualiza a entrada

        # Re-salvar todas as senhas no arquivo
        save_passwords(stored_passwords, master_password, salt)

        flash('Password updated successfully', 'success')
        return redirect(url_for('dashboard'))

    return render_template('edit_password.html', password_data=password_data)


@app.route('/delete_password/<title>', methods=['GET'])
@login_required
def delete_password(title):
    master_password = session.get('master_password')
    if not master_password:
        flash('Session expired. Please login again.', 'error')
        return redirect(url_for('login'))

    salt = b'initial_salt'  # Consistent salt for retrieval
    stored_passwords = get_stored_passwords(master_password, salt)

    # Filter out the password entry to delete
    updated_passwords = [p for p in stored_passwords if p['title'] != title]
    for password in stored_passwords:
        if password['title'] == title:
            url = password['url']
    delete_url_from_monitor(url)

    # Rewrite the file with the remaining passwords
    os.makedirs(os.path.dirname(Config.PASSWORDS_FILE), exist_ok=True)
    with open(Config.PASSWORDS_FILE, 'wb') as f:
        for entry in updated_passwords:
            encrypted_data = encrypt_data(entry, master_password, salt)
            entry_str = f"{entry['title']}: {encrypted_data.decode('utf-8')}\n"
            f.write(entry_str.encode('utf-8'))

    flash('Password deleted successfully', 'success')
    return redirect(url_for('dashboard'))


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not verify_master_password(current_password):
            flash('Current password is incorrect', 'error')
            return redirect(url_for('change_password'))
            
        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            return redirect(url_for('change_password'))
            
        salt = generate_salt()
        save_master_password(new_password, salt)
        
        flash('Password changed successfully', 'success')
        return redirect(url_for('dashboard'))
        
    return render_template('change_password.html')

@app.route('/dashboard')
@login_required
def dashboard():
    master_password = session.get('master_password')
    if not master_password:
        flash('Session expired. Please login again.', 'error')
        return redirect(url_for('login'))
        
    # Use a consistent salt for retrieval
    salt = b'initial_salt'  # Same as used in save_master_password
    stored_passwords = get_stored_passwords(master_password, salt)
    pwned_itens = check_password_pwned(stored_passwords)
    print(pwned_itens)
    return render_template('dashboard.html', passwords=stored_passwords,pwneds=pwned_itens)

@app.route('/generate_password', methods=['POST'])
@login_required
def generate_password():
    password = generate_random_password()
    return jsonify({'password': password})

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=False)


@app.route('/check_session')
def check_session():
    if 'last_activity' not in session:
        return jsonify({'expired': True})
        
    last_activity = datetime.fromisoformat(session['last_activity'])
    if datetime.now() - last_activity > timedelta(seconds=Config.SESSION_TIMEOUT):
        session.clear()
        return jsonify({'expired': True})
    return jsonify({'expired': False})
