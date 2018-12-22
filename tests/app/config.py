from os import urandom
from os.path import exists
from binascii import hexlify

class Config:
  DEBUG = True
  DEBUG_EMAILS = True
  TESTING = True

  HOST = "localhost"
  PUBLIC_HOST = HOST
  PORT = 8000
  SERVER_NAME = "http://{}:{}".format(PUBLIC_HOST, PORT)

  MONGO_TABLE = "tests"
  MONGO = {"host": PUBLIC_HOST, "port": 27017, "db": MONGO_TABLE}
  MONGO_URI = "mongodb://{host}:{port}/{db}".format(**MONGO)

  jwt_secret_file_path = "/run/secrets/jwt_secret"
  if exists(jwt_secret_file_path):
    with open(jwt_secret_file_path) as f:
      JWT_SECRET = f.read()
  else:
    JWT_SECRET = hexlify(urandom(32))
