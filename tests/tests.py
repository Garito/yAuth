from unittest import TestCase

from pymongo import MongoClient

from yAuth import generate_password_hash

from tests.app.app import create_app

class TestAuth(TestCase):
  def setUp(self):
    self.app = create_app()
    self.client = MongoClient(self.app.config["MONGO_URI"])
    self.table = self.client.tests.tests

    self.users = [
      {"type": "User", "email": "user1@email.com", "password": generate_password_hash("User1Password")},
      {"type": "User", "email": "user2@email.com", "password": generate_password_hash("User2Password")},
      {"type": "User", "email": "user3@email.com", "password": generate_password_hash("User3Password")}
    ]

    for user in self.users:
      result = self.table.insert_one(user)
      user["_id"] = result.inserted_id

  def tearDown(self):
    for user in self.users:
      self.table.delete_one({"_id": user["_id"]})

    self.client.close()

  def testAuthenticate(self):
    req, resp = self.app.test_client.post("/auth", json = {"email": "user3@email.com", "password": "User3Password"})

    self.assertEqual(resp.status, 200)
    self.assertIn("access_token", resp.json)

  def testRetrieveUser(self):
    req, resp = self.app.test_client.post("/auth", json = {"email": "user2@email.com", "password": "User2Password"})
    access_token = resp.json["access_token"]

    req, resp = self.app.test_client.get("/auth/me", headers = {"Authorization": "Bearer {}".format(access_token)})

    self.assertEqual(resp.status, 200)
    self.assertIn("me", resp.json)
    user = self.users[1].copy()
    del user["password"]
    user["_id"] = str(user["_id"])
    self.assertDictEqual(user, resp.json["me"])

  def testMalformedAuthentication(self):
    req, resp = self.app.test_client.post("/auth", json = {"name": "Garito", "password": "doesn'tcare"})

    self.assertEqual(resp.status, 401)
    self.assertIn("reasons", resp.json)
    self.assertListEqual(resp.json["reasons"], ['Authentication has failed'])

  def testInexistentUserAuthentication(self):
    req, resp = self.app.test_client.post("/auth", json = {"email": "idontexist@email.com", "password": "doesn'tcare"})

    self.assertEqual(resp.status, 401)
    self.assertIn("reasons", resp.json)
    self.assertListEqual(resp.json["reasons"], ['Authentication has failed'])
