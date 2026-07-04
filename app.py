import os
import logging
import secrets
import bcrypt
import requests
import psycopg2
import pyotp
import smtplib
from email.mime.text import MIMEText
from psycopg2.extras import RealDictCursor
from flask import Flask, render_template, request, jsonify, session, redirect, url_for

# =====================================================================
# SISTEMA DE AUDITORÍA (LOGS)
# =====================================================================
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] AUDIT_LOG: %(message)s')
logger = logging.getLogger("TrustNetAuditor")

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)

# =====================================================================
# CONFIGURACIÓN DE VARIABLES DE ENTORNO EN LA NUBE (RENDER)
# =====================================================================
MERCADOPAGO_ACCESS_TOKEN = os.environ.get("MP_ACCESS_TOKEN", "TEST-XXXXX")
MERCADOPAGO_PUBLIC_KEY = os.environ.get("MP_PUBLIC_KEY", "TEST-XXXXX")
DATABASE_URL = os.environ.get("DATABASE_URL")

SMTP_SERVER = os.environ.get("SMTP_SERVER", "://gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
SMTP_USER = os.environ.get("SMTP_USER", "tu-correo@gmail.com")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "tu-contraseña-aplicacion")

# =====================================================================
# MOTOR DE CONEXIÓN E INICIALIZACIÓN POSTGRESQL (PERSISTENTE)
# =====================================================================
def get_db_connection():
    return psycopg2.connect(DATABASE_URL, sslmode='require')

def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            username VARCHAR(50) PRIMARY KEY,
            rol VARCHAR(20) NOT NULL,
            password_hash BYTEA NOT NULL,
            saldo NUMERIC(12, 2) DEFAULT 0.0,
            secret_2fa VARCHAR(32) NOT NULL
        );
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS transacciones (
            id SERIAL PRIMARY KEY,
            usuario VARCHAR(50) REFERENCES usuarios(username),
            monto NUMERIC(12, 2) NOT NULL,
            estado VARCHAR(20) NOT NULL,
            motivo VARCHAR(100),
            fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    ''')
    cur.execute("SELECT COUNT(*) FROM usuarios WHERE username = 'admin';")
    if cur.fetchone() == 0:
        salt = bcrypt.gensalt()
        cur.execute("INSERT INTO usuarios (username, rol, password_hash, saldo, secret_2fa) VALUES (%s, %s, %s, %s, %s);",
                    ('admin', 'admin', bcrypt.hashpw(b"admin123", salt), 0.0, 'S7Z4N6Y7J3M9K2X1'))
        cur.execute("INSERT INTO usuarios (username, rol, password_hash, saldo, secret_2fa) VALUES (%s, %s, %s, %s, %s);",
                    ('juan_perez', 'user', bcrypt.hashpw(b"juan789", salt), 15000.0, 'J3M9K2X1S7Z4N6Y7'))
    conn.commit()
    cur.close()
    conn.close()

if DATABASE_URL:
    init_db()

def enviar_alerta_correo(usuario, monto, motivo):
    try:
        cuerpo = f"ALERTA CRÍTICA DE RIESGO:\n\nEl usuario '{usuario}' intentó procesar una carga de ${monto} y la tarjeta fue RECHAZADA por Mercado Pago.\n\nCódigo: {motivo}"
        msg = MIMEText(cuerpo)
        msg['Subject'] = f"⚠️ RECHAZO DE TARJETA - Usuario: {usuario}"
        msg['From'] = SMTP_USER
        msg['To'] = SMTP_USER
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(SMTP_USER, [SMTP_USER], msg.as_string())
        server.quit()
    except Exception as e:
        logger.error(f"Falla en el envío de mails: {e}")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form.get('username')
        password = request.form.get('password')
        token_2fa = request.form.get('token_2fa')
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT password_hash, secret_2fa FROM usuarios WHERE username = %s;", (user,))
        row = cur.fetchone()
        cur.close()
        conn.close()
        if row and bcrypt.checkpw(password.encode('utf-8'), bytes(row['password_hash'])):
            totp = pyotp.TOTP(row['secret_2fa'])
            if totp.verify(token_2fa):
                session['usuario'] = user
                return redirect(url_for('index'))
            else:
                return "Código 2FA incorrecto o expirado.", 401
        return "Credenciales inválidas", 401

    return '''
        <form method="post" style="max-width:320px; margin:50px auto; display:flex; flex-direction:column; gap:12px; font-family:sans-serif; background:#f4f6f9; padding:25px; border-radius:8px; box-shadow:0 4px 6px rgba(0,0,0,0.1);">
            <h2>TrustNet Core</h2>
            <input type="text" name="username" placeholder="Usuario" required style="padding:10px;">
            <input type="password" name="password" placeholder="Contraseña" required style="padding:10px;">
            <input type="text" name="token_2fa" placeholder="000000" required style="padding:10px; font-size:18px; text-align:center;" maxlength="6">
            <button type="submit" style="padding:12px; background:#009ee3; color:white; border:none; cursor:pointer;">Ingresar</button>
        </form>
    '''

@app.route('/')
def index():
    if 'usuario' not in session: return redirect(url_for('login'))
    usuario_activo = session['usuario']
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT rol, saldo, secret_2fa FROM usuarios WHERE username = %s;", (usuario_activo,))
    user_data = cur.fetchone()
    totp = pyotp.TOTP(user_data['secret_2fa'])
    qr_uri = totp.provisioning_uri(name=usuario_activo, issuer_name="TrustNetFamiliar")
    stats = {}
    if user_data['rol'] == 'admin':
        cur.execute("SELECT COUNT(*) FROM transacciones WHERE estado = 'approved';")
        stats['aprobados'] = cur.fetchone()['count']
        cur.execute("SELECT COUNT(*) FROM transacciones WHERE estado = 'rejected';")
        stats['rechazados'] = cur.fetchone()['count']
        cur.execute("SELECT username, saldo FROM usuarios WHERE rol != 'admin';")
        stats['saldos_usuarios'] = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('index.html', usuario=usuario_activo, rol=user_data['rol'], saldo=float(user_data['saldo']), public_key=MERCADOPAGO_PUBLIC_KEY, stats=stats, qr_uri=qr_uri)

@app.route('/logout')
def logout():
    session.pop('usuario', None)
    return redirect(url_for('login'))

@app.route('/process_payment', methods=['POST'])
def process_payment():
    if 'usuario' not in session: return jsonify({"status": "error"}), 403
    usuario_activo = session['usuario']
    payment_data = request.get_json()
    monto = float(payment_data.get("transaction_amount"))
    payload = {
        "token": payment_data.get("token"),
        "issuer_id": payment_data.get("issuer_id"),
        "payment_method_id": payment_data.get("payment_method_id"),
        "transaction_amount": monto,
        "installments": int(payment_data.get("installments")),
        "description": f"Carga Red Unificada - Usuario: {usuario_activo}",
        "payer": {"email": payment_data.get("payer", {}).get("email")}
    }
    headers = {"Authorization": f"Bearer {MERCADOPAGO_ACCESS_TOKEN}", "Content-Type": "application/json", "X-Idempotency-Key": secrets.token_hex(16)}
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        response = requests.post("https://mercadopago.com", json=payload, headers=headers)
        mp_response = response.get_json()
        if response.status_code == 201 and mp_response.get("status") == "approved":
            cur.execute("UPDATE usuarios SET saldo = saldo + %s WHERE username = %s;", (monto, usuario_activo))
            cur.execute("INSERT INTO transacciones (usuario, monto, estado, motivo) VALUES (%s, %s, %s, %s);", (usuario_activo, monto, 'approved', 'Cobro exitoso'))
            conn.commit()
            cur.execute("SELECT saldo FROM usuarios WHERE username = %s;", (usuario_activo,))
            return jsonify({"status": "success", "nuevo_saldo": float(cur.fetchone())})
        else:
            error_detail = mp_response.get("status_detail", "cc_rejected_other_reason")
            cur.execute("INSERT INTO transacciones (usuario, monto, estado, motivo) VALUES (%s, %s, %s, %s);", (usuario_activo, monto, 'rejected', error_detail))
            conn.commit()
            if error_detail in ["cc_rejected_high_risk", "cc_rejected_blacklist", "cc_rejected_fraud"]:
                enviar_alerta_correo(usuario_activo, monto, error_detail)
            return jsonify({"status": "rejected", "message": error_detail}), 400
    except Exception as e:
        conn.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500
    finally:
        cur.close()
        conn.close()

if __name__ == '__main__':
    app.run(debug=True, port=5000)
