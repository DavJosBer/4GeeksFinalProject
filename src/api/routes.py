"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
import re
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User, Ordenes, Service, ShopCart
from api.utils import generate_sitemap, APIException
from datetime import timedelta
from flask_jwt_extended import current_user
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

api = Blueprint('api', __name__)


@api.route('/', methods=['GET'])
def hello():
    
    response_body = {
        "message": "Hello! I'm a message that came from the backend"
    }

    return jsonify(response_body), 200

@api.route('/signup', methods=['POST'])
def create_user():
    
    body = request.get_json()
    user = User()
    
    if 'username' not in body:
        return jsonify({"msg": "username required"}),400
    if 'email' not in body:
        return jsonify({"msg": "email required"}),400
    if 'password' not in body:
        return jsonify({"msg": "password required"}),400
    if not re.match('^(\w|\.|\_|\-)+[@](\w|\_|\-|\.)+[.]\w{2,8}$', body['email']):
        return jsonify({"msg": "enter a valid format - check your email"})
    if not re.match('^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W])[^\n\t]{8,20}$', body['password']):
        return jsonify({"msg": "Password must contain the following: a lowercase letter, a capital letter, a number, one special character and minimum 8 characters"})

    username = User.query.filter_by(username=body['username']).first()
    email = User.query.filter_by(email=body['email']).first()

    if username:
        return jsonify({"msg": "This username already exists. Check your username"})
    if email:
        return jsonify({"msg": "This email already exists. Check your email"})
    
    user.username = body['username']
    user.email = body['email']
    user.password = body['password']
    user.address = body['address']

    db.session.add(user)
    db.session.commit()

    response_body = {
        'msg': "user commited"
    }

    return jsonify(response_body),200

@api.route("/login", methods=["POST"])
def login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    if username is None:
        return jsonify({"msg": "Username is required"}), 400
    if password is None:
        return jsonify({"msg": "Password is required"}),401
    
    user = User.query.filter_by(username=username).one_or_none()

    if not user:
        return jsonify({"msg": "Username doesn't exist"}), 400
    if not user.check_password(password):
        return jsonify({"msg": "Invalid password"}), 401
    
    expiration = timedelta(days=1)
    access_token = create_access_token(identity=user, expires_delta=expiration)
    return jsonify('The login has been successful.', {'token':access_token}), 200

