from marshmallow import fields

from yModel.mongo import ObjectId, MongoSchema

class User(MongoSchema):
  _id = ObjectId()
  type_ = fields.Str(attribute = "type", missing = "User")
  email = fields.Email(required = True)
  password = fields.Str()
