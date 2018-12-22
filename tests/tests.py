from unittest import TestCase

from pymongo import MongoClient

from tests.app.app import create_app

from json import dumps
from ySanic import MyEncoder

import jwt

class Tests(TestCase):
  def setUp(self):
    self.app = create_app()
    self.client = MongoClient(self.app.config["MONGO_URI"])
    self.table = self.client.tests.tests

  def tearDown(self):
    self.client.close()

  # def test(self):
  #   self.app.log.info(dumps(self.app._inspected, indent = 2, cls = MyEncoder))
  # #   self.app.log.info(self.app._inspected)
  # #   # self.app.log.info(self.app.router.routes_all)
  # #   self.app.log.info(dumps(self.app.router.routes_all, indent = 2, cls = MyEncoder))

  def login(self, data = None):
    if data is None:
      data = {"email": "garito@gmail.com", "password": "ASuperSecretPassword"}
    req, resp = self.app.test_client.get("/auth", json = data)
    self.assertEqual(resp.status, 200)
    self.assertIn("access_token", resp.json)
    return resp.json["access_token"]

  def auth_header(self, token = None):
    return {"Authorization": "Bearer {}".format(token or self.login())}

  def testAuth(self):
    token = self.login()
    admin = self.table.find_one({"email": "garito@gmail.com"})
    payload = jwt.decode(token, self.app.config["JWT_SECRET"], algorithms = ["HS256"])
    self.assertEqual(payload["user_id"], str(admin["_id"]))

  def testVerify(self):
    _, resp = self.app.test_client.get("/verify", headers = self.auth_header())
    self.assertEqual(resp.status, 200)
    self.assertTrue(resp.json["ok"])

  def testGetActor(self):
    _, resp = self.app.test_client.get("/get_actor", headers = self.auth_header())
    admin = self.table.find_one({"email": "garito@gmail.com"})
    self.assertEqual(resp.status, 200)
    self.assertTrue(resp.json["ok"])
    self.assertIn("result", resp.json)
    user = admin.copy()
    user["_id"] = str(user["_id"])
    del user["password"]
    self.assertDictEqual(user, resp.json["result"])
    
  def testAllowed(self):
    _, resp = self.app.test_client.get("/garito/get_trees", headers = self.auth_header())
    self.assertEqual(resp.status, 200)
    self.assertTrue(resp.json["ok"])
    self.assertIn("result", resp.json)
    self.assertEqual(resp.json["result"], [])

  def testNotAllowed(self):
    _, resp = self.app.test_client.get("/garito/get_trees")

    self.assertEqual(resp.status, 401)
    self.assertFalse(resp.json["ok"])
    self.assertIn("message", resp.json)
    self.assertEqual(resp.json["message"], "Not enought privileges")

  def testBadToken(self):
    _, resp = self.app.test_client.get("/garito/get_trees", headers = self.auth_header("badtoken"))

    self.assertEqual(resp.status, 401)
    self.assertFalse(resp.json["ok"])
    self.assertIn("message", resp.json)
    self.assertEqual(resp.json["message"], "Not enought privileges")

  def testBadLogin(self):
    _, resp = self.app.test_client.get("/auth", json = {"email": "garito@gmail.com", "password": "InvalidPassword"})

    self.assertEqual(resp.status, 401)
    self.assertFalse(resp.json["ok"])
    self.assertIn("message", resp.json)
    self.assertEqual(resp.json["message"], "Authentication has failed")

  def testGetActorBadToken(self):
    _, resp = self.app.test_client.get("/get_actor", headers = self.auth_header("badtoken"))

    self.assertEqual(resp.status, 401)
    self.assertFalse(resp.json["ok"])
    self.assertIn("message", resp.json)
    self.assertEqual(resp.json["message"], "Not enought privileges")