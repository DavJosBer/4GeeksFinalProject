from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import safe_str_cmp

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=False, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(80), unique=False, nullable=False)
    address = db.Column(db.String(250)) 
    client = db.relationship('ShopCart', backref='user', lazy=True)
    client_order = db.relationship('Ordenes', backref='user', lazy=True)

    def __repr__(self):
        return '<User %r>' % self.username

    def serialize(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "address": self.address
        }
    def check_password(self, password):
        return safe_str_cmp(password, self.password)

class ShopCart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name= db.Column(db.String(250))
    precio=db.Column(db.Integer)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    

    def __repr__(self):
        return '<Service %s>' % self.id

    def serialize(self):
        return {
            "id": self.id,
            "name": self.name,
            "precio": self.precio
        }

class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=False, nullable=False)
    description = db.Column(db.String(250), unique=True)
    precio = db.Column(db.Integer)
    client = db.relationship('ShopCart', backref='service', lazy=True)
    client_order = db.relationship('Ordenes', backref='service', lazy=True)

    def __repr__(self):
        return '<Service %s>' % self.name

    def serialize(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "precio": self.precio
        }

class Ordenes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    event_date = db.Column(db.String(250), unique=False, nullable=True)
    event_address = db.Column(db.String(512), unique=False, nullable=True)
    

    def __repr__(self):
        return '<Ordenes %s>' % self.id

    def serialize(self):
        return {
            "id": self.id
        }