"""
MyPasses - Password Manager Application
Main application module handling routes and user interactions.
"""

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from functools import wraps
from utils import (
    generate_salt, save_master_password, save_url_to_monitor, encrypt_data, save_passwords,
    verify_master_password, save_password_entry, get_stored_passwords, check_password_pwned,
    delete_url_from_monitor, generate_random_password
)
from config import Config
from datetime import datetime, timedelta
from crew.crew import SecurityCrew
import os, markdown

app = Flask(__name__)
app.config.from_object(Config)

def login_required(f):
    """Authentication and session management decorator."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'authenticated' not in session:
            return redirect(url_for('login'))
            
        if 'last_activity' in session:
            last_activity = datetime.fromisoformat(session['last_activity'])
            if datetime.now() - last_activity > timedelta(seconds=Config.SESSION_TIMEOUT):
                session.clear()
                flash('Sessão expirada. Por favor, faça login novamente.', 'error')
                return redirect(url_for('login'))
                
        session['last_activity'] = datetime.now().isoformat()
        return f(*args, **kwargs)
    return decorated_function

# Authentication Routes
@app.route('/')
def index():
    """Redirect to login page."""
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    if request.method == 'POST':
        password = request.form.get('password')
        
        if verify_master_password(password):
            session['authenticated'] = True
            session['master_password'] = password
            session['last_activity'] = datetime.now().isoformat()
            return redirect(url_for('dashboard'))
        flash('Senha inválida', 'error')
    
    needs_setup = not os.path.exists(Config.MASTER_PASSWORD_FILE)
    return render_template('login.html', needs_setup=needs_setup)

@app.route('/setup', methods=['POST'])
def setup():
    """Initial master password setup."""
    if os.path.exists(Config.MASTER_PASSWORD_FILE):
        flash('Configuração já realizada', 'error')
        return redirect(url_for('login'))
        
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    
    if password != confirm_password:
        flash('As senhas não coincidem', 'error')
        return redirect(url_for('login'))
        
    salt = generate_salt()
    save_master_password(password, salt)
    
    flash('Senha mestra criada com sucesso', 'success')
    return redirect(url_for('login'))

# Password Management Routes
@app.route('/add_password', methods=['GET', 'POST'])
@login_required
def add_password():
    """Add new password entry."""
    if request.method == 'GET':
        return render_template('add_password.html')
    
    master_password = session.get('master_password')
    if not master_password:
        flash('Sessão expirada. Por favor, faça login novamente.', 'error')
        return redirect(url_for('login'))

    data = {
        'title': request.form.get('title'),
        'username': request.form.get('username'),
        'password': request.form.get('password'),
        'url': request.form.get('url'),
        'notes': request.form.get('notes')
    }

    save_url_to_monitor(data['url'])
    save_password_entry(data['title'], data, master_password, b'initial_salt')
    flash('Senha adicionada com sucesso', 'success')
    return redirect(url_for('dashboard'))

@app.route('/edit_password/<title>', methods=['GET', 'POST'])
@login_required
def edit_password(title):
    """Edit existing password entry."""
    master_password = session.get('master_password')
    if not master_password:
        flash('Sessão expirada. Por favor, faça login novamente.', 'error')
        return redirect(url_for('login'))

    salt = b'initial_salt'
    stored_passwords = get_stored_passwords(master_password, salt)
    password_data = next((p for p in stored_passwords if p['title'] == title), None)

    if not password_data:
        flash('Senha não encontrada', 'error')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        updated_data = {
            'title': request.form.get('title'),
            'username': request.form.get('username'),
            'password': request.form.get('password'),
            'url': request.form.get('url'),
            'notes': request.form.get('notes')
        }

        for idx, entry in enumerate(stored_passwords):
            if entry['title'] == title:
                stored_passwords[idx] = updated_data

        save_passwords(stored_passwords, master_password, salt)
        flash('Senha atualizada com sucesso', 'success')
        return redirect(url_for('dashboard'))

    return render_template('edit_password.html', password_data=password_data)

@app.route('/delete_password/<title>', methods=['GET'])
@login_required
def delete_password(title):
    """Delete password entry."""
    master_password = session.get('master_password')
    if not master_password:
        flash('Sessão expirada. Por favor, faça login novamente.', 'error')
        return redirect(url_for('login'))

    salt = b'initial_salt'
    stored_passwords = get_stored_passwords(master_password, salt)
    updated_passwords = [p for p in stored_passwords if p['title'] != title]
    
    for password in stored_passwords:
        if password['title'] == title:
            delete_url_from_monitor(password['url'])

    os.makedirs(os.path.dirname(Config.PASSWORDS_FILE), exist_ok=True)
    with open(Config.PASSWORDS_FILE, 'wb') as f:
        for entry in updated_passwords:
            encrypted_data = encrypt_data(entry, master_password, salt)
            entry_str = f"{entry['title']}: {encrypted_data.decode('utf-8')}\n"
            f.write(entry_str.encode('utf-8'))

    flash('Senha deletada com sucesso', 'success')
    return redirect(url_for('dashboard'))

# Security Routes
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change master password and re-encrypt stored passwords."""
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not verify_master_password(current_password):
            flash('Senha atual incorreta', 'error')
            return redirect(url_for('change_password'))
            
        if new_password != confirm_password:
            flash('As novas senhas não coincidem', 'error')
            return redirect(url_for('change_password'))
            
        # Get current stored passwords before changing master password
        salt = b'initial_salt'
        stored_passwords = get_stored_passwords(current_password, salt)
        
        # Generate new salt and save new master password
        new_salt = generate_salt()
        save_master_password(new_password, new_salt)
        
        # Re-encrypt all stored passwords with new master password
        save_passwords(stored_passwords, new_password, salt)
        
        # Update session with new master password
        session['master_password'] = new_password
        
        flash('Senha alterada com sucesso', 'success')
        return redirect(url_for('dashboard'))
        
    return render_template('change_password.html')
@app.route('/run_crew')
@login_required
def run_crew():
    """Execute security crew analysis."""
    master_password = session.get('master_password')
    salt = b'initial_salt'
    stored_passwords = get_stored_passwords(master_password, salt)
    
    if not session.get('leaks', False):
        urls_to_monitor = [p['url'] for p in stored_passwords]
        crew = SecurityCrew()
        inputs = {
            'urls_to_monitor': urls_to_monitor, 
            'date': str(datetime.now())
        }
        try:
            data_leaks = str(crew.run(inputs=inputs))
            session['leaks'] = markdown.markdown(data_leaks)
        except Exception as e:
            flash(f'Erro ao executar a análise: {e}', 'error')
            session['leaks'] = "Erroo ao executar a análise"

    return session.get('leaks')

# Dashboard and Utility Routes
@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard view."""
    master_password = session.get('master_password')
    if not master_password:
        flash('Sessão expirada. Por favor, faça login novamente.', 'error')
        return redirect(url_for('login'))
        
    salt = b'initial_salt'
    stored_passwords = get_stored_passwords(master_password, salt)
    pwned_itens = check_password_pwned(stored_passwords)

    return render_template('dashboard.html', 
                         passwords=stored_passwords,
                         pwneds=pwned_itens, 
                         leaks=session.get('leaks'))

@app.route('/generate_password', methods=['POST'])
@login_required
def generate_password():
    """Generate random secure password."""
    password = generate_random_password()
    return jsonify({'password': password})

@app.route('/logout')
def logout():
    """User logout."""
    session.clear()
    return redirect(url_for('login'))

@app.route('/check_session')
def check_session():
    """Check session validity."""
    if 'last_activity' not in session:
        return jsonify({'expired': True})
        
    last_activity = datetime.fromisoformat(session['last_activity'])
    if datetime.now() - last_activity > timedelta(seconds=Config.SESSION_TIMEOUT):
        session.clear()
        return jsonify({'expired': True})
    return jsonify({'expired': False})

if __name__ == '__main__':
    app.run(debug=False)