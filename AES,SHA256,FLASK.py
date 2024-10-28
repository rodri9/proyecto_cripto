from flask import Flask, session, render_template, request, redirect, g, url_for, jsonify
from flask_socketio import SocketIO, send
import hashlib
import base64
import time  # Agregado para timestamp
from functools import wraps  # Para el decorador de login_required
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Hash import SHA256
except ImportError:
    from Cryptodome.Cipher import AES
    from Cryptodome.Random import get_random_bytes
    from Cryptodome.Hash import SHA256

app = Flask(__name__)
app.config['SECRET_KEY'] = "secret!123"
socketio = SocketIO(app, cors_allowed_origins="*")

# Almacenamiento de usuarios y sus claves
users = {
    'ximena': {'password': '1234', 'key': None},
    'alan': {'password': '123456', 'key': None}
}

# Almacenamiento de mensajes cifrados
encrypted_messages = []

# Decorador para requerir login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def generate_key():
    """Genera una nueva clave AES de 256 bits"""
    return get_random_bytes(32)

def hash_message(message):
    """Genera un hash SHA256 del mensaje"""
    if isinstance(message, str):
        message = message.encode()
    hash_object = SHA256.new(message)
    return hash_object.hexdigest()

def encrypt_message(message, key):
    """Encripta un mensaje usando AES en modo GCM y genera su hash"""
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    message_hash = hash_message(message)
    return ciphertext, tag, cipher.nonce, message_hash

def decrypt_message(ciphertext, tag, nonce, key, stored_hash):
    """Desencripta un mensaje usando AES en modo GCM y verifica su hash"""
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        decrypted_message = plaintext.decode('utf-8')
        
        current_hash = hash_message(decrypted_message)
        if current_hash != stored_hash:
            print("Warning: Message hash verification failed")
            return None
            
        return decrypted_message
    except ValueError as e:
        print("Descifrado fallido:", e)
        return None

def verify_message_integrity(message, stored_hash):
    """Verifica la integridad del mensaje comparando hashes"""
    current_hash = hash_message(message)
    return current_hash == stored_hash

@app.route('/', methods=['GET', 'POST'])
def index():
    if 'user' in session:
        return redirect(url_for('chat'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in users and users[username]['password'] == password:
            users[username]['key'] = generate_key()
            users[username]['password_hash'] = hash_message(password)
            session['user'] = username
            return redirect(url_for('chat'))
        else:
            return render_template('login.html', error="Usuario o contraseña incorrectos")
    
    return render_template('login.html')

@app.route('/chat')
@login_required
def chat():
    return render_template('index.html', user=session['user'])

@app.route('/protected')
@login_required
def protected():
    return render_template('protected.html', user=session['user'])

@app.route('/logout', methods=['POST'])
def logout():
    user = session.pop('user', None)
    if user in users:
        users[user]['key'] = None  # Eliminar la clave del usuario
    return redirect(url_for('index'))

@socketio.on('connect')
def handle_connect():
    if 'user' not in session:
        return False  # Rechazar conexión si no hay sesión

@socketio.on('message')
def handle_message(message):
    if 'user' not in session:
        return
    
    if message != "User connected!":
        username = session['user']
        user_key = users[username]['key']
        
        if user_key is None:
            print(f"Error: No key found for user {username}")
            return
        
        # Encripta el mensaje y genera hash
        ciphertext, tag, nonce, message_hash = encrypt_message(message, user_key)
        
        # Almacena el mensaje cifrado y su hash
        encrypted_message = {
            'sender': username,
            'ciphertext': ciphertext,
            'tag': tag,
            'nonce': nonce,
            'hash': message_hash,
            'timestamp': time.time()
        }
        encrypted_messages.append(encrypted_message)
        
        # Descifra y verifica el mensaje antes de enviarlo
        decrypted_message = decrypt_message(ciphertext, tag, nonce, user_key, message_hash)
        if decrypted_message:
            if verify_message_integrity(decrypted_message, message_hash):
                log_entry = {
                    'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
                    'tag': base64.b64encode(tag).decode('utf-8'),
                    'nonce': base64.b64encode(nonce).decode('utf-8'),
                    'hash': message_hash
                }
                print(f"Message sent by {username}:")
                print(f"Hash: {message_hash}")
                print(f"Encryption details: {log_entry}")
                
                send(f"{username}: {decrypted_message}", broadcast=True)
            else:
                print(f"Warning: Message integrity check failed for user {username}")
        else:
            print(f"Error: Failed to decrypt message from {username}")

@app.route('/get_message_info/<message_id>')
@login_required
def get_message_info(message_id):
    """Endpoint para obtener información sobre un mensaje específico"""
    try:
        message_id = int(message_id)
        if message_id >= len(encrypted_messages):
            return jsonify({'error': 'Invalid message ID'}), 404
            
        message = encrypted_messages[message_id]
        user_key = users[session['user']]['key']
        
        decrypted_content = decrypt_message(
            message['ciphertext'],
            message['tag'],
            message['nonce'],
            user_key,
            message['hash']
        )
        
        return jsonify({
            'sender': message['sender'],
            'hash': message['hash'],
            'timestamp': message['timestamp'],
            'verified': verify_message_integrity(decrypted_content, message['hash']) if decrypted_content else False,
            'decrypted': bool(decrypted_content)
        })
    except ValueError:
        return jsonify({'error': 'Invalid message ID format'}), 400

@app.before_request
def before_request():
    g.user = session.get('user', None)

if __name__ == "__main__":
    socketio.run(app, host="localhost", port=5000, debug=True)