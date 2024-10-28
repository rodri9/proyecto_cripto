from flask import Flask, render_template  # Importa Flask y render_template para crear la app y renderizar plantillas HTML
from flask_socketio import SocketIO, send  # Importa SocketIO para manejo de websockets y send para enviar mensajes

app = Flask(__name__)  # Crea una instancia de la aplicación Flask
app.config['SECRET_KEY'] = "secret!123"  # Configura una clave secreta para sesiones seguras en Flask
socketio = SocketIO(app, cors_allowed_origins="*")  # Inicializa SocketIO con la app Flask y permite conexiones de cualquier origen

@socketio.on('message')  # Define un manejador para el evento 'message' que llega a través de WebSocket
def handle_message(message):  # Función que maneja mensajes recibidos
    print("Received message: " + message)  # Imprime el mensaje recibido en la consola del servidor
    if message != "User connected!":  # Condición para ignorar el mensaje inicial de conexión
        send(message, broadcast=True)  # Envía el mensaje a todos los clientes conectados (broadcast)

@app.route('/')  # Define una ruta para la página principal de la aplicación
def index():  # Función para manejar las solicitudes a la página principal
    return render_template("index.html")  # Renderiza y envía la plantilla HTML 'index.html' al cliente

if __name__ == "__main__":  # Condicional para ejecutar el código solo si el archivo se ejecuta directamente
    socketio.run(app, host="localhost")  # Inicia la aplicación en modo WebSocket en localhost
