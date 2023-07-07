"""
My Python Project

This project aims to demonstrate various Python concepts and best practices.

Author: Richard O. Omondi
"""
import datetime
import os
import jwt
from flask import Flask, request
from flask_mysqldb import MySQL

server = Flask(__name__)
mysql = MySQL(server)

# config
server.config["MYSQL_HOST"] = os.environ.get("MYSQL_HOST")
server.config["MYSQL_USER"] = os.environ.get("MYSQL_USER")
server.config["MYSQL_PASSWORD"] = os.environ.get("MYSQL_PASSWORD")
server.config["MYSQL_DB"] = os.environ.get("MYSQL_DB")
server.config["MYSQL_PORT"] = os.environ.get("MYSQL_PORT")

@server.route("/login", methods=["POST"])
def login():
    """
    Perform user login.

    This function checks the provided credentials against the database and returns
    an appropriate response based on the authentication result.

    :return: A tuple containing the response message and status code.
    """
    auth = request.authorization
    if not auth:
        return "missing credentials", 401

    # check db for username and password
    cur = mysql.connection.cursor()
    res = cur.execute(
        "SELECT email, password FROM user WHERE email=%s", (auth.username,)
    )

    if res > 0:
        user_row = cur.fetchone()
        email = user_row[0]
        password = user_row[1]

        if auth.username != email or auth.password != password:
            return "Invalid credentials", 401

        return create_jwt(auth.username, os.environ.get("JWT_SECRET"), True)

    return "invalid credentials", 401

@server.route("/validate", methods=["POST"])
def validate():
    """
    Validates the authorization header for the request.

    This function the "Authorization" header from the request and checks if it exists.
    If the header is missing or empty, it returns a 'missing credentials' message with a 401 status code.

    Retuns:
        Tuple: A tuple containing the error message and HTTP status code.

    Example:
        >>> validate()
        ({'username': 'Richie', 'exp': 2012023, 'iat: 1172023', 'admin': True}, 200)
    """

    encoded_jwt = request.headers["Authorization"]

    if not encoded_jwt:
        return "missing credentials", 401

    encoded_jwt = encoded_jwt.split(" ")[1]

    try:
        decoded = jwt.decode(
            encoded_jwt, os.environ.get("JWT_SECRET"), algorithm=["HS256"]
        )
    except:
        return "not authorized", 403

    return decoded, 200


def create_jwt(username, secret, authz):
    """
    Create a JSON Web Token (JWT) with the provided payload

    This function provides a JWT using the provided username, secret and an authorization flag.
    The JWT contains information such as username, expiration time, issue-at-time and authorization flag.

    :param username: The username for which the JWT is being created.
    :param secret: The secret key used for signing the JWT.
    :param authz: The authorization flag indicating the user's privileges.

    :return: The generated JWT as a string.

    """
    return jwt.encode(
        {
            "username": username,
            "exp": datetime.datetime.now(tz=datetime.timezone.utc)
            + datetime.timedelta(days=1),
            "iat": datetime.datetime.utcnow(),
            "admin": authz,

        },
        secret,
        algorithm="HS256",
    )

if __name__ == "__main__":
    server.run(host="0.0.0.0", port=5000)
