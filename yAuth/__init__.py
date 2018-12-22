from os import urandom
from binascii import hexlify
from hashlib import pbkdf2_hmac
from secrets import compare_digest

from functools import wraps
from datetime import datetime, timedelta

from typing import Callable
from asyncio import iscoroutinefunction

from bson import ObjectId

import jwt

from marshmallow import fields
from marshmallow.exceptions import ValidationError

from sanic.exceptions import Unauthorized

from yModel import Schema, OkSchema, OkDictResult, produces, consumes, can_crash
from yModel.mongo import MongoSchema

from ySanic import notaroute

def generate_password_hash(password, salt = None, iterations = 50000):
  salt = hexlify(urandom(8)) if salt is None else str.encode(salt)
  password = str.encode(password)
  hex_hash = hexlify(pbkdf2_hmac("sha256", password, salt, iterations))

  return "pbkdf2:sha256:{}${}${}".format(iterations, salt.decode("utf-8"), hex_hash.decode("utf-8"))

def check_password_hash(hashed, password):
  conf, salt, thehash = hashed.split("$")
  test = generate_password_hash(password, salt)
  return compare_digest(test, hashed)

class InvalidRoute(Exception):
  pass

class PermissionException(Exception):
  pass

def allowed(condition):
  def decorator(func):
    if not hasattr(func, "__decorators__"):
      func.__decorators__ = {}
    func.__decorators__["allowed"] = {"condition": condition}

    @wraps(func)
    async def decorated(*args, **kwargs):
      request = None
      for arg in args:
        if hasattr(arg, "app") and hasattr(arg.app, "models"):
          request = arg
          break

      if request is None:
        raise InvalidRoute(func.__name__)

      authModel = yAuth()
      actor = await authModel._actor(request)

      if isinstance(condition, Callable):
        is_allowed = await condition(args, kwargs, actor) if iscoroutinefunction(condition) else condition(args, kwargs, actor)
        if is_allowed:
          return await func(*args, **kwargs)
      else:
        if hasattr(actor, "roles") and any(map(lambda rol: rol in condition, actor.roles)):
          return await func(*args, **kwargs)

      raise Unauthorized("Not enought privileges")

    return decorated
  return decorator

def permission(permission):
  def decorator(func):
    if not hasattr(func, "__decorators__"):
      func.__decorators__ = {}
    func.__decorators__["permission"] = permission

    @wraps(func)
    async def decorated(*args, **kwargs):
      request = None
      for arg in args:
        if hasattr(arg, "app") and hasattr(arg.app, "models"):
          request = arg
          break

      if request is None:
        raise InvalidRoute(func.__name__)

      authModel = yAuth()
      actor = await authModel._actor(request)

      parts = permission.split(".")
      parts.reverse()
      perm = request.app.permissions
      while parts:
        perm = perm[parts[-1]]
        parts.pop()

      if not perm:
        raise PermissionException("{} doesn't exists".format(permission))

      if any(map(lambda role: role in perm, actor.roles)):
        return await func(*args, **kwargs)
      else:
        raise Unauthorized("Not enought privileges")

    return decorated
  return decorator

class AuthToken(Schema):
  access_token = fields.Str()

  @classmethod
  def get_bearer(cls, headers, key = "Authorization", prefix = "Bearer"):
    return {"access_token": headers[key].replace("{} ".format(prefix), "")} if key in headers else None

  def generate(self, payload, secret, exp = 30, algo = "HS256"):
    if "exp" not in payload:
      payload["exp"] = datetime.utcnow() + timedelta(minutes = exp)
    self.__data__["access_token"] = jwt.encode(payload, secret, algo).decode()

  def verify(self, secret, algos = None):
    if algos is None:
      algos = ["HS256"]

    try:
      if self.get_data():
        payload = jwt.decode(self.access_token, secret, algorithms = algos)
        return payload
      else:
        return False
    except (jwt.DecodeError, jwt.ExpiredSignatureError):
      return False

class Auth(MongoSchema):
  email = fields.Email(required = True, label = "Email")
  password = fields.Str(required = True, label = "Password", input_type = "password")

class yAuth():
  @can_crash(ValidationError, code = 400, description = "Returns 400 is the login data can't be validated")
  @can_crash(Unauthorized, code = 401, description = "Returns Unauthorized if can't authorize")
  @produces(AuthToken, description = "Grants the user's access by returning a JWT token")
  @consumes("Auth")
  async def auth(self, request, model):
    user = await request.app.models.User.exists(self.table, model.email, True)

    if user and check_password_hash(user.password, model.password):
      token = AuthToken()
      token.generate({"user_id": str(user._id)}, request.app.config["JWT_SECRET"])
      return token.to_plain_dict()
    else:
      raise Unauthorized("Authentication has failed")

  @can_crash(Unauthorized, code = 401, description = "Returns Unauthorized if can't verify")
  @produces(OkSchema, description = "Verifies the user auth token")
  @allowed(["user"])
  async def verify(self, request):
    pass

  @notaroute
  @can_crash(Unauthorized, code = 401, renderer = lambda model: None)
  @produces("User", description = "")
  @consumes(AuthToken, from_ = "headers", getter = AuthToken.get_bearer)
  async def _actor(self, request, model):
    payload = model.verify(request.app.config["JWT_SECRET"])
    if payload:
      model = request.app.models.User(request.app.table, exclude = ("password",))
      await model.get(_id = ObjectId(payload["user_id"]))
      return model
    
    raise Unauthorized("No actor")

  @can_crash(Unauthorized, code = 401, description = "Returns Unauthorized if the token is invalid")
  @produces(OkDictResult, as_ = "result", description = "Returns the user data")
  @allowed(["user"])
  async def get_actor(self, request):
    actor = await self._actor(request)
    return actor.to_plain_dict()
