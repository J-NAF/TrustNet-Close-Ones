import os
from flask import Flask, render_template, request, redirect, url_inc, flash, session
import psycopg2
from psycopg2.extras import DictCursor
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'clave_secreta_trustnet_2026')

# Conexión automática a la base de datos Postgres de Render
def get_db_connection():
    url = os.environ.get('DATABASE_URL')
    return psycopg2.connect(url, cursor_factory=DictCursor)

# Crear la tabla de usuarios si no existe al arrancar
with get_db_connection() as conn:
    with conn.cursor() as cur:
        cur.execute('''
            CREATE TABLE IF NOT EXISTS usuarios (
                id SERIAL PRIMARY KEY,
                email VARCHAR(100) UNIQUE NOT NULL,
                username VARCHAR(50) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL
            );
        ''')
        conn.commit()

@app.route('/')
def index():
    if 'user' in session:
        return f"<h1>Bienvenido a TrustNet Core, {session['user']}!</h1><a href='/logout'>Cerrar Sesión</a>"
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not email or not username or not password:
            flash('Por favor, rellena todos los campos.')
            return redirect(url_for('register'))
            
        hashed_password = generate_password_hash(password)
        
        try:
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        'INSERT INTO usuarios (email, username, password) VALUES (%s, %s, %s)',
                        (email, username, hashed_password)
                    )
                    conn.commit()
            flash('¡Registro exitoso! Ya puedes iniciar sesión.')
            return redirect(url_for('login'))
        except psycopg2.IntegrityError:
            flash('El usuario o el email ya están registrados.')
            return redirect(url_for('register'))
            
    return '''
        <div style="max-width: 400px; margin: 50px auto; font-family: sans-serif;">
            <h2>Crear Cuenta - TrustNet Core</h2>
            <form method="POST">
                <p><input type="email" name="email" placeholder="Correo Electrónico" required style="width:100%; padding:10px;"></p>
                <p><input type="text" name="username" placeholder="Nombre de Usuario" required style="width:100%; padding:10px;"></p>
                <p><input type="password" name="password" placeholder="Contraseña" required style="width:100%; padding:10px;"></p>
                <button type="submit" style="width:100%; padding:10px; background:#007bff; color:white; border:none; cursor:pointer;">Registrarse</button>
            </form>
            <p><a href="/login">¿Ya tienes cuenta? Inicia sesión aquí</a></p>
        </div>
    '''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT * FROM usuarios WHERE username = %s', (username,))
                user = cur.fetchone()
                
        if user and check_password_hash(user['password'], password):
            session['user'] = user['username']
            return redirect(url_for('index'))
        else:
            flash('Usuario o contraseña incorrectos.')
            return redirect(url_for('login'))
            
    return '''
        <div style="max-width: 400px; margin: 50px auto; font-family: sans-serif;">
            <h2>Iniciar Sesión - TrustNet Core</h2>
            <form method="POST">
                <p><input type="text" name="username" placeholder="Usuario" required style="width:100%; padding:10px;"></p>
                <p><input type="password" name="password" placeholder="Contraseña" required style="width:100%; padding:10px;"></p>
                <button type="submit" style="width:100%; padding:10px; background:#28a745; color:white; border:none; cursor:pointer;">Ingresar</button>
            </form>
            <p><a href="/register">¿No tienes cuenta? Regístrate aquí</a></p>
        </div>
    '''

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
