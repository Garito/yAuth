from sanic_mongo import Mongo

from sanic_jwt import Initialize

from ySanic import MongoySanic

from yAuth import authenticate, retrieve_user

from tests.app import models
from tests.app.config import Config

def create_app():
  app = MongoySanic(models = models)
  app.config.from_object(Config)

  Mongo.SetConfig(app, test = app.config.get("MONGO_URI"))
  Mongo(app)

  Initialize(app, authenticate = authenticate, retrieve_user = retrieve_user)

  app.register_middleware(app.set_table, "request")

  if app.config.get("DEBUG", False):
    app.register_middleware(app.allow_origin, "response")

  return app

if __name__ == "__main__":
  app = create_app()
  app.run(host = app.config.get("HOST", "localhost"), port = app.config.get("PORT", 8000))
