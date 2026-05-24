# TALLER ELABORADO POR: JUAN DIEGO ACOSTA MOLINA

import ast
import base64
import hashlib
import html
import json
import os
import secrets

from flask import Flask, jsonify, request

app = Flask(__name__)
# SEGURIDAD: DEBUG controlado por variable de entorno, deshabilitado por defecto
# Previene: Configuración de depuración activa en entorno no seguro
app.config["DEBUG"] = os.environ.get("FLASK_DEBUG", "0") == "1"

# SEGURIDAD: SECRET_KEY se obtiene del entorno, NO está hardcodeada en el código
# Previene: Clave o secreto almacenado directamente en el código fuente
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
if not app.config["SECRET_KEY"]:
    raise RuntimeError("Missing SECRET_KEY environment variable")

# SEGURIDAD: Contraseñas hasheadas con PBKDF2-HMAC-SHA256, no en plano
# Previene: Información sensible escrita directamente en el código
DEFAULT_USERS = {
    "admin": "bN2ol8tP+GpQW+T6bVGNGfb1iNY/nifCi6+x9TmVC6R9Ts+ENy0G2Yh47f9G+zJ6",
    "cliente": "BORD8cYrfPfyKBdCKn4OvpEJJ4yWdS8x0Qlk/8J++bS+b5aRq3fMKm/Rp1iH5qEm",
}


def load_users():
    user_data = os.environ.get("APP_USERS_JSON")
    if not user_data:
        return DEFAULT_USERS
    try:
        parsed = json.loads(user_data)
    except json.JSONDecodeError as exc:
        raise RuntimeError("APP_USERS_JSON must be valid JSON") from exc
    if not isinstance(parsed, dict) or not all(isinstance(v, str) for v in parsed.values()):
        raise RuntimeError("APP_USERS_JSON must map usernames to hashed passwords")
    return parsed


users = load_users()
active_sessions = {}


def verify_password(password: str, stored_hash: str) -> bool:
    # SEGURIDAD: Decodifica y verifica hash con PBKDF2-HMAC-SHA256
    # Previene: Comparación insegura de contraseñas en plano
    try:
        raw = base64.b64decode(stored_hash.encode("utf-8"))
    except (TypeError, ValueError):
        return False

    if len(raw) != 48:
        return False

    salt, key = raw[:16], raw[16:]
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
    
    # SEGURIDAD: Usa compare_digest() para evitar timing attacks
    # Previene: Ataques de tiempo que revelan longitud del hash
    return secrets.compare_digest(candidate, key)


def create_session_token(username: str) -> str:
    # SEGURIDAD: Genera token criptográficamente seguro con secrets
    # Previene: Valor fijo usado como mecanismo de seguridad
    # Cada login genera un token único e impredecible
    token = secrets.token_urlsafe(32)
    active_sessions[token] = username
    return token


def get_authenticated_user():
    # SEGURIDAD: Autentica usuario verificando Bearer token en header
    # Previene: Endpoint crítico sin ningún tipo de protección
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header.split(" ", 1)[1]
    return active_sessions.get(token)


def safe_arithmetic(expr: str):
    # SEGURIDAD: Parsea y valida la expresión con AST antes de ejecutar
    # Previene: Ejecución de expresiones provenientes del usuario sin validación
    node = ast.parse(expr, mode="eval")
    
    # SEGURIDAD: Solo permite operaciones aritméticas, bloquea todo lo demás
    # Previene: Ejecución de código arbitrario via eval()
    allowed_nodes = (
        ast.Expression,
        ast.BinOp,
        ast.UnaryOp,
        ast.Constant,
        ast.Add,
        ast.Sub,
        ast.Mult,
        ast.Div,
        ast.Pow,
        ast.Mod,
        ast.UAdd,
        ast.USub,
        ast.FloorDiv,
        ast.BitAnd,
        ast.BitOr,
        ast.BitXor,
        ast.LShift,
        ast.RShift,
    )
    for subnode in ast.walk(node):
        if not isinstance(subnode, allowed_nodes):
            raise ValueError("Expresión no permitida")
        # SEGURIDAD: Valida que las constantes sean solo numéricas
        # Previene: Inyección de strings o tipos peligrosos
        if isinstance(subnode, ast.Constant) and not isinstance(subnode.value, (int, float)):
            raise ValueError("Solo se permiten valores numéricos")
    
    # SEGURIDAD: Ejecuta con __builtins__ vacío, previene acceso a funciones peligrosas
    # Previene: Acceso a funciones del sistema desde eval()
    return eval(compile(node, "<string>", "eval"), {"__builtins__": None}, {})



@app.route("/login", methods=["POST"])
def login():
    # SEGURIDAD: Valida que el JSON sea válido y que sea un diccionario
    # Previene: Falta de verificación de datos recibidos en una petición
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Solicitud JSON inválida"}), 400

    username = data.get("username")
    password = data.get("password")
    
    # SEGURIDAD: Valida tipos de datos y que no estén vacíos
    # Previene: Entrada del usuario utilizada sin ningún tipo de filtro
    if not isinstance(username, str) or not username or not isinstance(password, str) or not password:
        return jsonify({"error": "username y password son obligatorios"}), 400

    stored_hash = users.get(username)
    
    # SEGURIDAD: Compara contraseña hasheada, genera token seguro
    # Previene: Comparación de contraseñas en plano, tokens predecibles
    if stored_hash and verify_password(password, stored_hash):
        return jsonify({"message": "Login exitoso", "token": create_session_token(username)})

    # SEGURIDAD: Mensaje genérico que no revela si usuario existe o no
    # Previene: Respuesta que expone información interna del sistema
    return jsonify({"error": "Credenciales inválidas"}), 401


@app.route("/admin")
def admin():
    # SEGURIDAD: Valida autenticación antes de permitir acceso
    # Previene: Endpoint crítico sin ningún tipo de protección
    username = get_authenticated_user()
    if username != "admin":
        return jsonify({"error": "Acceso no autorizado"}), 403
    return jsonify({"message": "Acceso administrativo validado"})


@app.route("/search")
def search():
    q = request.args.get("q", "")
    
    # SEGURIDAD: Valida que el parámetro sea string
    # Previene: Falta de verificación de datos recibidos en una petición
    if not isinstance(q, str):
        return jsonify({"error": "Parámetro q inválido"}), 400
    
    # SEGURIDAD: Limita tamaño máximo de entrada para prevenir abuso
    # Previene: Ataques DoS y límites razonables en búsquedas
    if len(q) > 100:
        return jsonify({"error": "Parámetro q demasiado largo"}), 400

    # SEGURIDAD: Devuelve query parametrizada, NO concatenada
    # Previene: Construcción de consultas sin control de entrada (SQL Injection)
    # El driver de BD deberá usar los parámetros de forma segura
    return jsonify({"query": "SELECT * FROM users WHERE name = %s", "params": [q]})


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "0")
    
    # SEGURIDAD: Valida que la entrada sea string
    # Previene: Falta de verificación de datos recibidos en una petición
    if not isinstance(expr, str):
        return jsonify({"error": "Parámetro expr inválido"}), 400
    try:
        # SEGURIDAD: Usa safe_arithmetic para validar y ejecutar solo operaciones seguras
        # Previene: Ejecución de expresiones provenientes del usuario sin validación
        result = safe_arithmetic(expr)
    except ValueError:
        # SEGURIDAD: Captura y retorna errores sin exponer detalles de ejecución
        # Previene: Respuesta que expone información interna del sistema
        return jsonify({"error": "Expresión no permitida"}), 400

    return jsonify({"result": result})


@app.route("/echo")
def echo():
    msg = request.args.get("msg")
    
    # SEGURIDAD: Valida que el parámetro sea obligatorio
    # Previene: Falta de verificación de datos recibidos en una petición
    if msg is None:
        return jsonify({"error": "Parámetro msg es obligatorio"}), 400
    
    # SEGURIDAD: Escapa el mensaje para prevenir XSS
    # Previene: Entrada del usuario utilizada sin ningún tipo de filtro
    # y Respuesta que expone información interna del sistema
    return jsonify({"message": html.escape(msg)})


if __name__ == "__main__":
    # SEGURIDAD: Ejecuta la app en modo seguro
    # En producción, usar un servidor WSGI como Gunicorn
    # Requiere SECRET_KEY en variables de entorno
    app.run(host="0.0.0.0", port=5000)
