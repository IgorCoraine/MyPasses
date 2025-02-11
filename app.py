from flask import Flask, render_template, request, redirect, url_for, flash, session
from functools import wraps
import os
from utils import (
    generate_salt, hash_password, save_master_password, 
    verify_master_password
)
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'authenticated' not in session:
            return redirect(url_for('login'))
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
            return redirect(url_for('dashboard'))
        flash('Invalid password', 'error')
    
    # Check if first time setup is needed
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
    hashed_password = hash_password(password, salt)
    save_master_password(hashed_password, salt)
    
    flash('Master password created successfully', 'success')
    return redirect(url_for('login'))

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
        hashed_password = hash_password(new_password, salt)
        save_master_password(hashed_password, salt)
        
        flash('Password changed successfully', 'success')
        return redirect(url_for('dashboard'))
        
    return render_template('change_password.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=False)
