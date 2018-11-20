from os import urandom
from binascii import hexlify
from hashlib import pbkdf2_hmac
from secrets import compare_digest
from functools import wraps
from typing import Callable

from marshmallow import fields
from marshmallow.validate import Length

from sanic.request import Request
from sanic.exceptions import Unauthorized, InvalidUsage

from sanic_jwt.exceptions import AuthenticationFailed

from ySanic import yBlueprint, response
from yModel import Schema

def generate_password_hash(password, salt = None, iterations = 50000):
  salt = hexlify(urandom(8)) if salt is None else str.encode(salt)
  password = str.encode(password)
  hex_hash = hexlify(pbkdf2_hmac("sha256", password, salt, iterations))

  return "pbkdf2:sha256:{}${}${}".format(iterations, salt.decode("utf-8"), hex_hash.decode("utf-8"))

def check_password_hash(hashed, password):
  conf, salt, thehash = hashed.split("$")
  test = generate_password_hash(password, salt)
  return compare_digest(test, hashed)

class Auth(Schema):
  email = fields.Email(required = True)
  password = fields.Str(required = True, validate = [Length(min = 6)])

  def authenticates(self, password):
    return check_password_hash(password, self.get_data()["password"])

  async def exists(self):
    return await self.table.find_one({"type": "User", "email": self.get_data()["email"]})

async def authenticate(request, *args, **kwargs):
  model = Auth(request.app.table)
  model.load(request.json)
  if model.get_errors():
    raise AuthenticationFailed("Authentication has failed")

  user = await model.exists()
  if not user or not model.authenticates(user["password"]):
    raise AuthenticationFailed("Authentication has failed")

  return user

async def retrieve_user(request, payload, *args, **kwargs):
  if payload and request.app.config["SANIC_JWT_USER_ID"] in payload:
    user_id = payload[request.app.config["SANIC_JWT_USER_ID"]]
    if user_id:
      model = request.app.models.User(request.app.table, exclude = ("password",))
      await model.get(**{request.app.config["SANIC_JWT_USER_ID"]: user_id})
      if hasattr(model, "post_retrieve_user"):
        model.post_retrieve_user(request, payload, *args, **kwargs)

      return model.to_plain_dict()

  return None

async def actor_model(request):
  payload = request.app.auth.extract_payload(request, verify = False)
  user = await request.app.auth.retrieve_user(request, payload)
  if user:
    model = request.app.models.User(request.app.table)
    model.load(user)
  else:
    model = None

  return model

def get_actor(func):
  async def decorator(*args, **kwargs):
    request = args[1]
    newargs = list(args)
    newargs.append(await actor_model(request))

    return await func(*newargs, **kwargs)

  return decorator

def allowed(condition):
  def decorator(func):
    if not hasattr(func, "__decorators__"):
      func.__decorators__ = {}
    func.__decorators__["allowed"] = {"condition": condition}

    @wraps(func)
    async def decorated(*args, **kwargs):
      request = None
      for arg in args:
        if isinstance(arg, Request):
          request = arg
          break
      if request is None:
        raise InvalidUsage(func.__name__)

      actor = await actor_model(request)

      if isinstance(condition, Callable):
        if condition(args[0], actor):
          return await func(*args, **kwargs)
      else:
        if hasattr(actor, "roles") and any(map(lambda rol: rol in condition, actor.roles)):
          return await func(*args, **kwargs)

      raise Unauthorized("Not enought privileges")

    return decorated
  return decorator

def add_manage_password_routes():
  bp = yBlueprint('manage_password')

  @bp.options("/<slug>/change_password")
  def change_password_options(request, *args, **kwargs):
    return response.text("", status = 204)

  @bp.post("/<slug>/change_password")
  @bp.can_crash(Unauthorized, code = 401)
  @bp.produces()
  async def change_password(request, slug, *args, **kwargs):
    model = request.app.models.User(request.app.table)
    await model.get(slug = slug)
    await model.change_password(request, *args, **kwargs)

  @bp.options("/reset_password")
  def reset_password_options(request, *args, **kwargs):
    return response.text("", status = 204)

  @bp.post("/reset_password")
  async def reset_password(request):
    model = request.app.models.ResetPasswordRequest(request.app.table)
    model.load(request.json)
    user = request.app.models.User(request.app.table)
    try:
      await user.get(email = model.email)
      await model.create()
      request.app.notify("reset_password", {"user": user.get_data(), "data": model.get_data()})
    except Exception as e:
      request.app.log.info(e)
    return response.json({"ok": True})

  return bp
