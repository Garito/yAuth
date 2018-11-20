# yAuth
yAuth is an integration of [yModel](https://github.com/Garito/yModel), [ySanic](https://github.com/Garito/ySanic) and [sanic-jwt](https://github.com/ahopkins/sanic-jwt)

It has the authenticate and the retrieve_user necessary to log in your users

It has a password generator and checker inspired on the flask one (better not reinvent the wheel with security)

In addition to that, it has a decorator to get the user that makes the query (the actor) and the routes to manage the password and to reset it

# Example
```python
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
  app.blueprint(add_manage_password_routes())

  app.register_middleware(app.set_table, "request")

  if app.config.get("DEBUG", False):
    app.register_middleware(app.allow_origin, "response")

  return app

if __name__ == "__main__":
  app = create_app()
  app.run(host = app.config.get("HOST", "localhost"), port = app.config.get("PORT", 8000))
```

As a normal patter for sanic, the example shows a create_app function that setups the ySanic (yMongoSanic, the mongo sanic version, in this case)

Creates the object and configures it

Setups the MongoClient (the async Motor version in this case)

Then setups the sanic-jwt in the ```Initialize``` using the provided ```authenticate``` and ```retrieve_user```

And finally adds the password management routes with ```add_manage_password_routes```

## Installation
```pip install yAuth```

## Help
Feel free to help if you think something is weird or incomplete by submiting a pull request

### What is already needed
- [] More testing
- [] Continous integration
- [] Better help & documentation

### I'm not a technical person but still want to help
You can tip the project with cryptos too:

BTC: 1GtKxwZGR65ar9V8xafxhMiniZyqXej2GC

ETH: 0x01bd478b8C07633D2f4E58AC553f72CE4E590d56

LTC: LYUzrFX6ck5uMhw5VqcD9piQHnX7oeSLdh

XMR: 49stcvbfjEkWLjb6mdG21zMJ3uRrLmN3bazGQ8cHjjsVHYYyY61N6P7emCXhpsvB2Vc8Uuz2FA1Qk6hkE8e4ADmJQQ64eyT

ADA: DdzFFzCqrhsoUF5UjGGAYUayV5uNCJZ17PJn9V8X9MTQ26m2wDVycme42gufKufPNWMazfJLg8RKHpc1iFvn6j8BTJjaozGtLPzCDx5t

NEM: NDGYO6X3NTD6CX3V7MCCYKQPBIOYGZRXEKDLCDW2
