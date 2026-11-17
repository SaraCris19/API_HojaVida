import re
from contextlib import contextmanager
from datetime import date, datetime, timedelta
from functools import wraps

import mysql.connector
from flask import Flask, request, jsonify
from flask.json.provider import DefaultJSONProvider
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, get_jwt, get_jwt_identity, jwt_required
from werkzeug.security import generate_password_hash, check_password_hash

from database import conectar_bd


class JSONProvider(DefaultJSONProvider):
    ensure_ascii = False
    sort_keys = False

    def default(self, o):
        if isinstance(o, (date, datetime)):
            return o.isoformat()
        return super().default(o)


app = Flask(__name__)
app.json = JSONProvider(app)
app.config["JWT_SECRET_KEY"] = "sena-adso-hoja-de-vida-2026-clave-secreta-jwt"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=4)
CORS(app)
jwt = JWTManager(app)

PATRON_CORREO = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


class ErrorConexion(Exception):
    pass


@contextmanager
def base_datos():
    db = conectar_bd()
    if db is None:
        raise ErrorConexion()
    cursor = db.cursor(dictionary=True)
    try:
        yield db, cursor
    finally:
        cursor.close()
        db.close()


@app.errorhandler(ErrorConexion)
def error_conexion(_):
    return jsonify({"mensaje": "No se pudo conectar con la base de datos"}), 500


@app.errorhandler(mysql.connector.Error)
def error_mysql(error):
    return jsonify({"mensaje": "Error en la base de datos", "detalle": str(error)}), 500


@jwt.unauthorized_loader
def token_ausente(_):
    return jsonify({"mensaje": "Debes iniciar sesión para acceder"}), 401


@jwt.invalid_token_loader
def token_invalido(_):
    return jsonify({"mensaje": "Token inválido"}), 401


@jwt.expired_token_loader
def token_expirado(_header, _payload):
    return jsonify({"mensaje": "La sesión expiró, inicia sesión de nuevo"}), 401


def rol_requerido(rol):
    def decorador(funcion):
        @wraps(funcion)
        @jwt_required()
        def wrapper(*args, **kwargs):
            claims = get_jwt()
            if claims.get("rol") != rol:
                return jsonify({"mensaje": "No tienes permisos para acceder"}), 403
            return funcion(*args, **kwargs)
        return wrapper
    return decorador


def leer_json():
    datos = request.get_json(silent=True)
    return datos if isinstance(datos, dict) else None


def campos_vacios(datos, campos):
    return [campo for campo in campos if str(datos.get(campo) or "").strip() == ""]


def respuesta_campos(vacios):
    return jsonify({"mensaje": "Todos los campos son obligatorios", "campos": vacios}), 400


def entero(valor, minimo, maximo):
    try:
        numero = int(valor)
    except (TypeError, ValueError):
        return None
    return numero if minimo <= numero <= maximo else None


def fecha(valor):
    try:
        return datetime.strptime(str(valor), "%Y-%m-%d").date()
    except ValueError:
        return None


def usuario_actual():
    return int(get_jwt_identity())


def hoja_del_usuario(cursor, hoja_vida_id, usuario_id):
    cursor.execute(
        "SELECT id FROM hojas_vida WHERE id = %s AND usuario_id = %s",
        (hoja_vida_id, usuario_id)
    )
    return cursor.fetchone()


def hoja_completa(cursor, hv):
    hoja_vida_id = hv["id"]

    cursor.execute(
        "SELECT id, nivel, institucion, titulo, anio_graduacion FROM estudios WHERE hoja_vida_id = %s ORDER BY anio_graduacion DESC, id",
        (hoja_vida_id,)
    )
    estudios = cursor.fetchall()

    cursor.execute(
        "SELECT id, nombre, institucion, horas, anio FROM cursos WHERE hoja_vida_id = %s ORDER BY anio DESC, id",
        (hoja_vida_id,)
    )
    cursos = cursor.fetchall()

    cursor.execute(
        "SELECT id, empresa, cargo, area, fecha_ingreso, fecha_retiro, funciones FROM experiencias WHERE hoja_vida_id = %s ORDER BY fecha_ingreso DESC, id",
        (hoja_vida_id,)
    )
    experiencias = cursor.fetchall()

    cursor.execute("""
        SELECT h.id, h.nombre, h.experiencia_id
        FROM habilidades h
        INNER JOIN experiencias e ON h.experiencia_id = e.id
        WHERE e.hoja_vida_id = %s
        ORDER BY h.id
    """, (hoja_vida_id,))
    habilidades = cursor.fetchall()

    for experiencia in experiencias:
        experiencia["habilidades"] = [
            h for h in habilidades if h["experiencia_id"] == experiencia["id"]
        ]

    return {
        "datos_personales": hv,
        "estudios": estudios,
        "cursos": cursos,
        "experiencias": experiencias,
        "habilidades": habilidades
    }


@app.route("/api/registro-usuario", methods=["POST"])
def registro_usuario():
    datos = leer_json()
    if not datos:
        return jsonify({"mensaje": "No se recibieron datos"}), 400

    nombre = str(datos.get("nombre") or "").strip()
    correo = str(datos.get("correo") or "").strip().lower()
    password = str(datos.get("password") or "")

    if not nombre or not correo or not password.strip():
        return jsonify({"mensaje": "Todos los campos son obligatorios"}), 400

    if not PATRON_CORREO.match(correo):
        return jsonify({"mensaje": "El correo no tiene un formato válido"}), 400

    if len(password) < 8 or len(password) > 15:
        return jsonify({"mensaje": "La contraseña debe tener entre 8 y 15 caracteres"}), 400

    with base_datos() as (db, cursor):
        cursor.execute("SELECT id FROM usuarios WHERE correo = %s", (correo,))
        if cursor.fetchone():
            return jsonify({"mensaje": "El correo ya está registrado"}), 409

        password_hash = generate_password_hash(password)
        cursor.execute(
            "INSERT INTO usuarios (nombre, correo, password, rol) VALUES (%s, %s, %s, 'aprendiz')",
            (nombre, correo, password_hash)
        )
        db.commit()
        nuevo_id = cursor.lastrowid

    return jsonify({
        "mensaje": "Usuario registrado correctamente",
        "usuario": {"id": nuevo_id, "nombre": nombre, "correo": correo, "rol": "aprendiz"}
    }), 201


@app.route("/api/login", methods=["POST"])
def login():
    datos = leer_json()
    if not datos:
        return jsonify({"mensaje": "No se recibieron datos"}), 400

    correo = str(datos.get("correo") or "").strip().lower()
    password = str(datos.get("password") or "")

    if not correo or not password:
        return jsonify({"mensaje": "Correo y contraseña son obligatorios"}), 400

    with base_datos() as (_, cursor):
        cursor.execute(
            "SELECT id, nombre, correo, password, rol, estado FROM usuarios WHERE correo = %s",
            (correo,)
        )
        usuario = cursor.fetchone()

    if not usuario or not check_password_hash(usuario["password"], password):
        return jsonify({"mensaje": "Correo o contraseña incorrectos"}), 401

    if not usuario["estado"]:
        return jsonify({"mensaje": "Cuenta desactivada"}), 403

    token = create_access_token(
        identity=str(usuario["id"]),
        additional_claims={"rol": usuario["rol"]}
    )

    return jsonify({
        "mensaje": "Inicio de sesión correcto",
        "token": token,
        "usuario": {
            "id": usuario["id"],
            "nombre": usuario["nombre"],
            "correo": usuario["correo"],
            "rol": usuario["rol"]
        }
    }), 200


@app.route("/api/hojas-vida", methods=["GET"])
@rol_requerido("reclutador")
def obtener_hojas():
    with base_datos() as (_, cursor):
        cursor.execute("""
            SELECT hv.id, hv.usuario_id, hv.nombre, hv.apellidos, hv.edad, hv.ciudad, hv.correo,
                   hv.fotografia, hv.programa, hv.ficha, hv.jornada, hv.fecha_registro,
                   (SELECT COUNT(*) FROM estudios e WHERE e.hoja_vida_id = hv.id) AS total_estudios,
                   (SELECT COUNT(*) FROM cursos c WHERE c.hoja_vida_id = hv.id) AS total_cursos,
                   (SELECT COUNT(*) FROM experiencias x WHERE x.hoja_vida_id = hv.id) AS total_experiencias
            FROM hojas_vida hv
            ORDER BY hv.fecha_registro DESC
        """)
        hojas = cursor.fetchall()

    return jsonify({"total": len(hojas), "hojas_vida": hojas}), 200


@app.route("/api/hojas-vida/<int:hoja_vida_id>", methods=["GET"])
@rol_requerido("reclutador")
def obtener_hoja(hoja_vida_id):
    with base_datos() as (_, cursor):
        cursor.execute("SELECT * FROM hojas_vida WHERE id = %s", (hoja_vida_id,))
        hv = cursor.fetchone()
        if not hv:
            return jsonify({"mensaje": "Hoja de vida no encontrada"}), 404
        resultado = hoja_completa(cursor, hv)

    return jsonify(resultado), 200


@app.route("/api/registrohv", methods=["POST"])
@rol_requerido("aprendiz")
def registrohv():
    usuario_id = usuario_actual()
    datos = leer_json()
    if not datos:
        return jsonify({"mensaje": "No se recibieron datos"}), 400

    vacios = campos_vacios(datos, ["nombre", "apellidos", "edad", "ciudad", "correo", "programa", "ficha", "jornada"])
    if vacios:
        return respuesta_campos(vacios)

    edad = entero(datos["edad"], 14, 100)
    if edad is None:
        return jsonify({"mensaje": "La edad debe ser un número entre 14 y 100"}), 400

    correo = str(datos["correo"]).strip().lower()
    if not PATRON_CORREO.match(correo):
        return jsonify({"mensaje": "El correo no tiene un formato válido"}), 400

    with base_datos() as (db, cursor):
        cursor.execute("SELECT id FROM hojas_vida WHERE usuario_id = %s", (usuario_id,))
        existente = cursor.fetchone()
        if existente:
            return jsonify({
                "mensaje": "Ya tienes una hoja de vida registrada",
                "hoja_vida_id": existente["id"]
            }), 409

        sql = """
            INSERT INTO hojas_vida
            (usuario_id, nombre, apellidos, edad, ciudad, correo, fotografia, programa, ficha, jornada, perfil)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        valores = (
            usuario_id,
            str(datos["nombre"]).strip(),
            str(datos["apellidos"]).strip(),
            edad,
            str(datos["ciudad"]).strip(),
            correo,
            str(datos.get("fotografia") or "").strip() or None,
            str(datos["programa"]).strip(),
            str(datos["ficha"]).strip(),
            str(datos["jornada"]).strip(),
            str(datos.get("perfil") or "").strip() or None
        )
        cursor.execute(sql, valores)
        db.commit()
        nuevo_id = cursor.lastrowid

    return jsonify({"mensaje": "Hoja de vida registrada correctamente", "hoja_vida_id": nuevo_id}), 201


@app.route("/api/mi-hoja-vida", methods=["GET"])
@rol_requerido("aprendiz")
def mi_hoja_vida():
    usuario_id = usuario_actual()

    with base_datos() as (_, cursor):
        cursor.execute("SELECT * FROM hojas_vida WHERE usuario_id = %s", (usuario_id,))
        hv = cursor.fetchone()
        if not hv:
            return jsonify({"mensaje": "Aún no has registrado tu hoja de vida"}), 404
        resultado = hoja_completa(cursor, hv)

    return jsonify(resultado), 200


@app.route("/api/hojas-vida/<int:hoja_vida_id>/estudios", methods=["POST"])
@rol_requerido("aprendiz")
def registrar_estudio(hoja_vida_id):
    datos = leer_json()
    if not datos:
        return jsonify({"mensaje": "No se recibieron datos"}), 400

    vacios = campos_vacios(datos, ["nivel", "institucion", "titulo", "anio_graduacion"])
    if vacios:
        return respuesta_campos(vacios)

    anio = entero(datos["anio_graduacion"], 1950, date.today().year + 10)
    if anio is None:
        return jsonify({"mensaje": "El año de graduación no es válido"}), 400

    with base_datos() as (db, cursor):
        if not hoja_del_usuario(cursor, hoja_vida_id, usuario_actual()):
            return jsonify({"mensaje": "Hoja de vida no encontrada"}), 404

        cursor.execute("""
            INSERT INTO estudios (hoja_vida_id, nivel, institucion, titulo, anio_graduacion)
            VALUES (%s, %s, %s, %s, %s)
        """, (hoja_vida_id, str(datos["nivel"]).strip(), str(datos["institucion"]).strip(),
              str(datos["titulo"]).strip(), anio))
        db.commit()
        nuevo_id = cursor.lastrowid

    return jsonify({"mensaje": "Estudio registrado correctamente", "id": nuevo_id, "hoja_vida_id": hoja_vida_id}), 201


@app.route("/api/hojas-vida/<int:hoja_vida_id>/cursos", methods=["POST"])
@rol_requerido("aprendiz")
def registrar_curso(hoja_vida_id):
    datos = leer_json()
    if not datos:
        return jsonify({"mensaje": "No se recibieron datos"}), 400

    vacios = campos_vacios(datos, ["nombre", "institucion", "horas", "anio"])
    if vacios:
        return respuesta_campos(vacios)

    horas = entero(datos["horas"], 1, 10000)
    if horas is None:
        return jsonify({"mensaje": "Las horas deben ser un número mayor a 0"}), 400

    anio = entero(datos["anio"], 1950, date.today().year)
    if anio is None:
        return jsonify({"mensaje": "El año del curso no es válido"}), 400

    with base_datos() as (db, cursor):
        if not hoja_del_usuario(cursor, hoja_vida_id, usuario_actual()):
            return jsonify({"mensaje": "Hoja de vida no encontrada"}), 404

        cursor.execute("""
            INSERT INTO cursos (hoja_vida_id, nombre, institucion, horas, anio)
            VALUES (%s, %s, %s, %s, %s)
        """, (hoja_vida_id, str(datos["nombre"]).strip(), str(datos["institucion"]).strip(), horas, anio))
        db.commit()
        nuevo_id = cursor.lastrowid

    return jsonify({"mensaje": "Curso registrado correctamente", "id": nuevo_id, "hoja_vida_id": hoja_vida_id}), 201


@app.route("/api/hojas-vida/<int:hoja_vida_id>/experiencias", methods=["POST"])
@rol_requerido("aprendiz")
def registrar_experiencia(hoja_vida_id):
    datos = leer_json()
    if not datos:
        return jsonify({"mensaje": "No se recibieron datos"}), 400

    vacios = campos_vacios(datos, ["empresa", "cargo", "area", "fecha_ingreso", "fecha_retiro", "funciones"])
    if vacios:
        return respuesta_campos(vacios)

    ingreso = fecha(datos["fecha_ingreso"])
    retiro = fecha(datos["fecha_retiro"])
    if not ingreso or not retiro:
        return jsonify({"mensaje": "Las fechas deben tener el formato AAAA-MM-DD"}), 400

    if retiro < ingreso:
        return jsonify({"mensaje": "La fecha de retiro no puede ser anterior a la de ingreso"}), 400

    if ingreso > date.today():
        return jsonify({"mensaje": "La fecha de ingreso no puede ser futura"}), 400

    with base_datos() as (db, cursor):
        if not hoja_del_usuario(cursor, hoja_vida_id, usuario_actual()):
            return jsonify({"mensaje": "Hoja de vida no encontrada"}), 404

        cursor.execute("""
            INSERT INTO experiencias (hoja_vida_id, empresa, cargo, area, fecha_ingreso, fecha_retiro, funciones)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (hoja_vida_id, str(datos["empresa"]).strip(), str(datos["cargo"]).strip(),
              str(datos["area"]).strip(), ingreso, retiro, str(datos["funciones"]).strip()))
        db.commit()
        nuevo_id = cursor.lastrowid

    return jsonify({"mensaje": "Experiencia registrada correctamente", "id": nuevo_id, "hoja_vida_id": hoja_vida_id}), 201


@app.route("/api/experiencias/<int:experiencia_id>/habilidades", methods=["POST"])
@rol_requerido("aprendiz")
def registrar_habilidad(experiencia_id):
    usuario_id = usuario_actual()
    datos = leer_json() or {}

    nombre = str(datos.get("nombre") or "").strip()
    if not nombre:
        return jsonify({"mensaje": "El nombre de la habilidad es obligatorio"}), 400

    with base_datos() as (db, cursor):
        cursor.execute("""
            SELECT e.id
            FROM experiencias e
            INNER JOIN hojas_vida hv ON hv.id = e.hoja_vida_id
            WHERE e.id = %s AND hv.usuario_id = %s
        """, (experiencia_id, usuario_id))
        if not cursor.fetchone():
            return jsonify({"mensaje": "Experiencia no encontrada"}), 404

        cursor.execute(
            "SELECT id FROM habilidades WHERE experiencia_id = %s AND nombre = %s",
            (experiencia_id, nombre)
        )
        if cursor.fetchone():
            return jsonify({"mensaje": "Esa habilidad ya está registrada en esta experiencia"}), 409

        cursor.execute(
            "INSERT INTO habilidades (experiencia_id, nombre) VALUES (%s, %s)",
            (experiencia_id, nombre)
        )
        db.commit()
        nuevo_id = cursor.lastrowid

    return jsonify({"mensaje": "Habilidad registrada correctamente", "id": nuevo_id, "experiencia_id": experiencia_id}), 201


if __name__ == "__main__":
    app.run(debug=True, port=5000)
