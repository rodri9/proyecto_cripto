from flask import Flask, session, render_template, request, redirect, g, url_for, jsonify
from flask_socketio import SocketIO, send
import hashlib
import base64
import time
from functools import wraps
try:
    from Crypto.Cipher import AES, PKCS1_OAEP
    from Crypto.Random import get_random_bytes
    from Crypto.Hash import SHA256
    from Crypto.PublicKey import RSA
except ImportError:
    from Cryptodome.Cipher import AES, PKCS1_OAEP
    from Cryptodome.Random import get_random_bytes
    from Cryptodome.Hash import SHA256
    from Cryptodome.PublicKey import RSA

app = Flask(__name__)
app.config['SECRET_KEY'] = "secret!123"
socketio = SocketIO(app, cors_allowed_origins="*")

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

users = {
    'ximena': {
        'password': '1234',
        'salt': None,
        'key': None,
        'private_key': None,
        'public_key': None
    },
    'alan': {
        'password': '123456',
        'salt': None,
        'key': None,
        'private_key': None,
        'public_key': None
    }
}

def assign_rsa_keys(username):
    private_key, public_key = generate_rsa_keys()
    users[username]['private_key'] = private_key
    users[username]['public_key'] = public_key

def derive_key(password, salt=None):
    if salt is None:
        salt = get_random_bytes(16)
    
    if isinstance(password, str):
        password = password.encode()
    
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password,
        salt,
        100000,
        dklen=32
    )
    
    return key, salt

encrypted_messages = []

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def encrypt_aes_key_with_rsa(aes_key, public_key):
    try:
        rsa_public_key = RSA.import_key(public_key)
        cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
        return cipher_rsa.encrypt(aes_key)
    except Exception as e:
        print(f"Error en encrypt_aes_key_with_rsa: {e}")
        return None

def decrypt_aes_key_with_rsa(encrypted_aes_key, private_key):
    try:
        rsa_private_key = RSA.import_key(private_key)
        cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
        return cipher_rsa.decrypt(encrypted_aes_key)
    except Exception as e:
        print(f"Error en decrypt_aes_key_with_rsa: {e}")
        return None

def generate_key():
    return get_random_bytes(32)

def hash_message(message):
    if isinstance(message, str):
        message = message.encode()
    hash_object = SHA256.new(message)
    return hash_object.hexdigest()

def encrypt_message(message, key):
    try:
        if not key:
            raise ValueError("La clave de cifrado es None")
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(message.encode())
        message_hash = hash_message(message)
        return ciphertext, tag, cipher.nonce, message_hash
    except Exception as e:
        print(f"Error en encrypt_message: {e}")
        return None, None, None, None

def decrypt_message(ciphertext, tag, nonce, key, stored_hash):
    try:
        if not key:
            raise ValueError("La clave de descifrado es None")
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        decrypted_message = plaintext.decode('utf-8')
        
        current_hash = hash_message(decrypted_message)
        if current_hash != stored_hash:
            print("Warning: Message hash verification failed")
            return None
            
        return decrypted_message
    except Exception as e:
        print(f"Error en decrypt_message: {e}")
        return None

def verify_message_integrity(message, stored_hash):
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
            print(f"\n=== Login de usuario: {username} ===")
            
            # Generamos la clave AES
            aes_key = generate_key()
            print(f"Clave AES generada: {base64.b64encode(aes_key).decode()}")
            
            # Generamos la clave derivada y el salt usando PBKDF2
            derived_key, salt = derive_key(password)
            
            print(f"Salt generado: {base64.b64encode(salt).decode() if salt else 'None'}")
            print(f"Longitud de la clave derivada: {len(derived_key)} bytes")
            
            # Almacenamos las claves y el salt
            users[username]['salt'] = salt
            users[username]['key'] = aes_key  # Usamos la clave AES en lugar de la derivada
            users[username]['password_hash'] = hash_message(password)

            # Asignamos las claves RSA
            assign_rsa_keys(username)
            print("Claves RSA generadas y asignadas")

            session['user'] = username
            session['key'] = base64.b64encode(aes_key).decode()  # Guardamos la clave en la sesión
            
            print("=== Login completado ===\n")
            return redirect(url_for('chat'))
        else:
            return render_template('login.html', error="Usuario o contraseña incorrectos")
    
    return render_template('login.html')

@app.route('/chat')
@login_required
def chat():
    return render_template('index.html', user=session['user'])

@socketio.on('connect')
def handle_connect():
    if 'user' not in session:
        return False
    print(f"Usuario {session['user']} conectado")

@socketio.on('message')
def handle_message(message):
    if 'user' not in session:
        return
    
    if message != "User connected!":
        try:
            username = session['user']
            
            # Recuperamos la clave de la sesión
            if 'key' not in session:
                print("Error: No hay clave en la sesión")
                return
                
            user_key = base64.b64decode(session['key'])
            if not user_key:
                print("Error: Clave inválida")
                return
            
            recipient = username
            recipient_public_key = users[recipient]['public_key']
            
            if not recipient_public_key:
                print(f"Error: No se encontró la clave pública para {recipient}")
                return
            
            encrypted_aes_key = encrypt_aes_key_with_rsa(user_key, recipient_public_key)
            if not encrypted_aes_key:
                print("Error: No se pudo cifrar la clave AES")
                return
            
            ciphertext, tag, nonce, message_hash = encrypt_message(message, user_key)
            if not all([ciphertext, tag, nonce, message_hash]):
                print("Error: No se pudo cifrar el mensaje")
                return
            
            encrypted_message = {
                'sender': username,
                'ciphertext': ciphertext,
                'tag': tag,
                'nonce': nonce,
                'encrypted_aes_key': encrypted_aes_key,
                'hash': message_hash,
                'timestamp': time.time()
            }
            encrypted_messages.append(encrypted_message)
            
            decrypted_message = decrypt_message(ciphertext, tag, nonce, user_key, message_hash)
            if decrypted_message:
                if verify_message_integrity(decrypted_message, message_hash):
                    log_entry = {
                        'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
                        'tag': base64.b64encode(tag).decode('utf-8'),
                        'nonce': base64.b64encode(nonce).decode('utf-8'),
                        'hash': message_hash,
                        'encrypted_aes_key': base64.b64encode(encrypted_aes_key).decode('utf-8')
                    }
                    print(f"Message sent by {username}:")
                    print(f"Hash: {message_hash}")
                    print(f"Encryption details: {log_entry}")
                    
                    send(f"{username}: {decrypted_message}", broadcast=True)
                else:
                    print(f"Warning: Message integrity check failed for user {username}")
            else:
                print(f"Error: Failed to decrypt message from {username}")
        except Exception as e:
            print(f"Error en handle_message: {e}")

@app.route('/logout', methods=['POST'])
def logout():
    user = session.pop('user', None)
    session.pop('key', None)  # Eliminamos la clave de la sesión
    if user in users:
        users[user]['key'] = None
    return redirect(url_for('index'))

if __name__ == "__main__":
    socketio.run(app, host="localhost", port=5000, debug=True)
