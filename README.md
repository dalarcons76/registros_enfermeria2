# Enfermería escolar — MVP Flask + SQLite

Aplicación interna para centralizar el registro de atenciones, gestionar la cola de espera y generar constancias del alumno y del profesor desde una única atención.

## Incluye

- Inicio de sesión con contraseñas hasheadas y roles (`admin`, `enfermeria`).
- Directorio y búsqueda de alumnos.
- Registro único de atención con estados: espera, atención y finalizada.
- Cola de espera y resumen diario.
- Constancia imprimible para el alumno y constancia administrativa para el profesor. La copia del profesor no incluye detalles clínicos.
- Historial de atenciones.
- Importación CSV inicial y exportación del directorio.
- Auditoría básica de acciones.
- Protección CSRF en formularios, consultas SQL parametrizadas, cookies HttpOnly/SameSite.
- SQLite con claves foráneas, WAL y timeout para escrituras concurrentes.

## Estructura

```text
registro_enfermeria/
├── app.py
├── app/                  # Conserva la carpeta de aplicación del repositorio base
├── instance/             # Se crea automáticamente; NO subir a Git
├── static/
│   └── style.css
├── templates/
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```

## Instalación (Windows)

Abre PowerShell en la carpeta del proyecto:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:FLASK_SECRET_KEY = py -c "import secrets; print(secrets.token_hex(32))"
flask --app app crear-admin
```

El comando `crear-admin` pide un usuario y una contraseña de al menos 12 caracteres. Guarda la contraseña en un gestor institucional. Luego inicia el servidor LAN:

```powershell
waitress-serve --listen=0.0.0.0:5000 app:app
```

En el computador servidor abre `http://127.0.0.1:5000`. Desde otros computadores de la red, abre `http://IP-DEL-SERVIDOR:5000`.

Para conocer la IP privada del servidor usa `ipconfig`. Configura el firewall para permitir el puerto TCP 5000 solo en la red privada institucional. No publiques el puerto en Internet. Mantén el computador servidor encendido, con acceso restringido y copias de seguridad protegidas.

## Instalación (Linux/macOS)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export FLASK_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
flask --app app crear-admin
waitress-serve --listen=0.0.0.0:5000 app:app
```

## Importación de alumnos

Desde **Alumnos → Importar CSV**, sube un CSV UTF-8 con estos encabezados exactos:

```csv
identificador_escolar,nombre,apellido,curso
A1024,Valentina,Ejemplo,2° Medio A
,Benjamín,Prueba,7° Básico B
```

El identificador escolar puede quedar vacío. Se omiten filas incompletas y los identificadores duplicados. Exportar alumnos crea un archivo CSV con encabezados `identificador_escolar,nombre,apellido,curso,activo`.

La importación/exportación de este MVP es un formato propio y **no es una integración directa con Kimche**. Antes de intercambiar datos con Kimche, confirmar con el colegio y el proveedor que existe un método autorizado, qué campos pueden exportarse y cuál es la base legal para hacerlo.

## Pruebas manuales de aceptación

1. Iniciar sesión como administrador.
2. Crear un usuario de enfermería desde el menú Usuarios.
3. Registrar o importar un alumno.
4. Crear una atención; debe aparecer en la cola como “En espera”.
5. Abrir la atención, iniciar, completar acciones e indicaciones y guardar.
6. Abrir ambas constancias; imprimir o guardar como PDF.
7. Finalizar la atención; debe quedar en el historial y mostrar la hora de salida.
8. Cerrar sesión y verificar que el panel redirige al inicio de sesión.

## Limitaciones importantes antes de usar datos reales

Este es un MVP técnico, no un producto clínico validado. Antes de almacenar datos reales de menores, el colegio debe aprobar el flujo, los campos, la retención, los roles, las copias de seguridad y las medidas de privacidad. El despliegue de ejemplo usa HTTP dentro de la LAN: no lo expongas a redes públicas; para uso institucional real, usa HTTPS, controles de acceso de red, gestión segura de secretos y pruebas de seguridad. La constancia del alumno contiene información de atención; entrega solo al destinatario correcto.

SQLite es razonable para una aplicación interna con un único proceso servidor y pocos usuarios concurrentes. No compartas el archivo SQLite directamente por una carpeta de red: todos los equipos deben usar la aplicación Flask a través del navegador. Si la concurrencia de escritura crece, evalúa PostgreSQL.

## Kimche

No hay sincronización automática incluida. Este MVP permite cargar y descargar el directorio en CSV genérico, no garantiza compatibilidad con los formatos de Kimche. No importar información clínica desde el sistema del colegio sin autorización expresa.
