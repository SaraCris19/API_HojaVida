import mysql.connector


def conectar_bd():
    try:
        conexion = mysql.connector.connect(
            host="localhost",
            user="root",
            password="",
            database="hojadevida2026_sarac"
        )
        return conexion
    except mysql.connector.Error as err:
        print(f"Error al conectar con la base de datos: {err}")
        return None
