import re
from getpass import getpass

from werkzeug.security import generate_password_hash

from database import conectar_bd


def crear_administrador():
    nombre = input("Nombre del reclutador: ").strip()
    correo = input("Correo electrónico: ").strip().lower()
    password = getpass("Contraseña (8 a 15 caracteres): ")
    confirmacion = getpass("Confirmar contraseña: ")

    if not nombre or not correo or not password:
        print("Todos los campos son obligatorios")
        return

    if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", correo):
        print("El correo no tiene un formato válido")
        return

    if len(password) < 8 or len(password) > 15:
        print("La contraseña debe tener entre 8 y 15 caracteres")
        return

    if password != confirmacion:
        print("Las contraseñas no coinciden")
        return

    conexion = conectar_bd()
    if conexion is None:
        return

    cursor = conexion.cursor()

    try:
        cursor.execute("SELECT id FROM usuarios WHERE correo = %s", (correo,))
        if cursor.fetchone():
            print("Este correo ya está registrado")
            return

        password_hash = generate_password_hash(password)
        sql = """
            INSERT INTO usuarios (nombre, correo, password, rol, estado)
            VALUES (%s, %s, %s, 'reclutador', 1)
        """
        cursor.execute(sql, (nombre, correo, password_hash))
        conexion.commit()
        print("Reclutador creado correctamente")

    except Exception as error:
        conexion.rollback()
        print("Error:", error)
    finally:
        cursor.close()
        conexion.close()


if __name__ == "__main__":
    crear_administrador()
