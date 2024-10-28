from flask import Flask, session, render_template, request, redirect, g, url_for
from flask_socketio import SocketIO, send

app = Flask(__name__)
app.config['SECRET_KEY'] = "secret!123"
socketio = SocketIO(app, cors_allowed_origins="*")  # Inicializa SocketIO

# Definición de usuarios y contraseñas permitidos
users = {
    'ximena': '1234',
    'alan': '123456'
}

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        session.pop('user', None)
        
        username = request.form['username']
        password = request.form['password']

        # Verificar si el usuario y la contraseña son correctos
        if username in users and users[username] == password:
            session['user'] = username
            return redirect(url_for('chat'))  # Redirigir a la página de chat
    
    return render_template('login.html')  # Página de inicio de sesión

@app.route('/chat')
def chat():
    return render_template('index.html', user=session['user'])  # Renderiza index.html como página de chat

@app.before_request
def before_request():
    g.user = None
    if 'user' in session:
        g.user = session['user']

@socketio.on('message')  # Define un manejador para el evento 'message'
def handle_message(message):
    print("Received message: " + message)  # Imprime el mensaje recibido
    if message != "User connected!":  # Ignorar el mensaje inicial de conexión
        send(message, broadcast=True)  # Envía el mensaje a todos los clientes conectados

if __name__ == "__main__":
    socketio.run(app, host="localhost", debug=True)  # Inicia la aplicación
