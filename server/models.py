from sqlalchemy.ext.hybrid import hybrid_property
from marshmallow import Schema, fields

from config import db, bcrypt

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    _password_hash = db.Column(db.String, nullable=False)

    # Protect direct access to password_hash
    @hybrid_property
    def password_hash(self):
        raise AttributeError("Password hashes may not be viewed.")

    # Set password hash using bcrypt
    @password_hash.setter
    def password_hash(self, password):
        self._password_hash = bcrypt.generate_password_hash(
            password.encode('utf-8')
        ).decode('utf-8')

    # Authenticate a user by comparing hash to entered password
    def authenticate(self, password):
        return bcrypt.check_password_hash(
            self._password_hash.encode('utf-8'),
            password.encode('utf-8')
        )

    def __repr__(self):
        return f'<User {self.username}, ID: {self.id}>'

class UserSchema(Schema):
    id = fields.Int()
    username = fields.String()
