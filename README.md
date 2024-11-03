# Secure Communication Protocol Implementation

Este proyecto implementa un protocolo de comunicación seguro utilizando Flask y SocketIO. Proporciona autenticación, encriptación de mensajes, firmas digitales y verificación de integridad para asegurar la comunicación entre usuarios en tiempo real.

## Características

- **Autenticación de Usuarios**: Manejo de inicio de sesión de usuarios mediante credenciales almacenadas.
- **Cifrado de Mensajes**: Utiliza el algoritmo AES para cifrar los mensajes antes de enviarlos.
- **Firmas Digitales**: Los mensajes son firmados con RSA para asegurar la autenticidad.
- **Verificación de Integridad**: SHA-256 asegura que los mensajes no hayan sido alterados.
- **Conexiones en Tiempo Real**: Integración con SocketIO para comunicación instantánea entre clientes.

## Tecnologías

- **Python**: Lenguaje de programación utilizado.
- **Flask**: Framework web para manejar rutas y lógica de la aplicación.
- **SocketIO**: Protocolo para conexiones en tiempo real.
- **Crypto/Cryptodome**: Librería de criptografía para RSA, AES, SHA-256 y manejo de claves.
- **PBKDF2**: Algoritmo para derivar claves seguras a partir de contraseñas.

## Instalación

1. Clona este repositorio:
   ```bash
   git clone https://github.com/tuusuario/tu-repositorio.git
   cd tu-repositorio
   ```

## Uso

1. Ejecuta la aplicación:
   ```bash
   python app.py
   ```

2. Abre tu navegador y accede a `http://localhost:5000` para ver la aplicación.

3. Inicia sesión con uno de los usuarios preconfigurados (`ximena` o `alan`) y prueba la funcionalidad de chat seguro en tiempo real.

## Estructura del Proyecto

- `app.py`: Archivo principal que configura la aplicación, define las rutas, la lógica de encriptación, y maneja la comunicación en tiempo real.
- `templates/`: Contiene las plantillas HTML para las páginas de inicio de sesión y chat.

## Ejemplo de Usuarios Preconfigurados

- **Usuario**: `ximena` | **Contraseña**: `1234`
- **Usuario**: `alan` | **Contraseña**: `123456`

## Seguridad

- **Clave AES**: Generada para cada sesión de usuario.
- **Cifrado RSA**: Usado para cifrar la clave AES compartida.
- **Firma y Verificación**: Asegura que los mensajes sean auténticos.

## Contribución

Si deseas contribuir:
1. Haz un fork del proyecto.
2. Crea una nueva rama (`git checkout -b nueva-funcionalidad`).
3. Realiza los cambios y haz commit (`git commit -am 'Añadir nueva funcionalidad'`).
4. Sube los cambios a tu rama (`git push origin nueva-funcionalidad`).
5. Crea un Pull Request.

## Licencia

Este proyecto está bajo la Licencia MIT. Consulta el archivo [LICENSE](LICENSE) para más información.
