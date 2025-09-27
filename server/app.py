#!/usr/bin/env python3

from flask import Flask, request, session, jsonify
from flask_migrate import Migrate
from flask_restful import Api, Resource

from config import db
from models import User, UserSchema

app = Flask(__name__)
app.secret_key = b'super-secret-key'  # you can keep/change this
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.json.compact = False

migrate = Migrate(app, db)
db.init_app(app)

api = Api(app)

user_schema = UserSchema()


# ---------- SIGNUP ----------
class Signup(Resource):
    def post(self):
        data = request.get_json()

        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return {"error": "Username and password required"}, 400

        # Create new user
        new_user = User(username=username)
        new_user.password_hash = password  # setter will hash the password

        db.session.add(new_user)
        db.session.commit()

        # Log them in by saving ID in session
        session["user_id"] = new_user.id

        return user_schema.dump(new_user), 201


# ---------- LOGIN ----------
class Login(Resource):
    def post(self):
        data = request.get_json()

        username = data.get("username")
        password = data.get("password")

        user = User.query.filter_by(username=username).first()

        if user and user.authenticate(password):
            session["user_id"] = user.id
            return user_schema.dump(user), 200

        return {"error": "Invalid username or password"}, 401


# ---------- LOGOUT ----------
class Logout(Resource):
    def delete(self):
        session.pop("user_id", None)
        return "", 204


# ---------- CHECK SESSION ----------
class CheckSession(Resource):
    def get(self):
        user_id = session.get("user_id")

        if not user_id:
            return "", 204

        user = User.query.get(user_id)
        if not user:
            return "", 204

        return user_schema.dump(user), 200


# ---------- ROUTES ----------
api.add_resource(Signup, "/signup")
api.add_resource(Login, "/login")
api.add_resource(Logout, "/logout")
api.add_resource(CheckSession, "/check_session")


if __name__ == "__main__":
    app.run(port=5555, debug=True)
