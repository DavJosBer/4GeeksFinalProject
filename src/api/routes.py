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

#Devuelve servicios fetch-GET

@api.route('/hello', methods=['GET'])
def get_service():
    #service = Service.query.all()
    #all_services = list(map(lambda service: service.serialize(), service))
    #return jsonify(all_services), 200
    response_body = {
        "message": "cualquier cosa"
    }
    return jsonify(response_body),200

#*******************************************************************************#

#Sign Up fetch-POST

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

#******************************************************************************************

#Login fetch-POST JWT Auth
# todo match username + password

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

#**********************************************************************************************

#shopCart access, add services

@api.route('/shopCart', methods=['POST'])
@jwt_required()
def create_shopCart():
    current_user_id = get_jwt_identity()
    
    body = request.get_json()

    if body is None:
        return jsonify({"msg": "Body Null"}),400
    if 'service_id' not in body:
        return jsonify({"msg": "Especifique id del servicio"}),400
    if 'precio' not in body:
        return jsonify({"msg": "Especifique precio del servicio"}),400
    if 'cantidad' not in body:
        return jsonify({"msg": "Especifique cantidad del servicio"}),400
        
    
    shopCart = ShopCart()
    shopCart.user_id = current_user_id
    shopCart.service_id = body['service_id']
    shopCart.precio = body['precio']
    shopCart.cantidad = body['cantidad']

    db.session.add(shopCart) # agrega el favorito a la base de datos
    db.session.commit() # guarda los cambios

    user_shopCart = ShopCart.query.filter_by(user_id=current_user_id)
    user_shopCart = list(map(lambda x: x.serialize(), user_shopCart))

    return jsonify(user_shopCart), 200

#*********************************************************************

#Delete articles in shopCart

@api.route('/shopCart', methods=['DELETE'])
@jwt_required()
def delete_favorites():
    current_user_id = get_jwt_identity()
    body = request.get_json()
    if body is None:
        return jsonify({"msg": "Body Null"}),400
    if 'id' not in body:
        return jsonify({"msg": "Especifique id del servicio"}),400
    user_shopCart_id = ShopCart.query.filter_by(user_id=current_user_id, id=body['id']).first()
    db.session.delete(user_shopCart_id) # elimina el favorito de la base de datos
    db.session.commit() # guarda los cambios
    user_shopCart_id = ShopCart.query.filter_by(user_id=current_user_id)
    user_shopCart_id = list(map(lambda x: x.serialize(), user_shopCart_id))
    return jsonify(user_shopCart_id), 200

#************************************************************************

@api.route('/ordenes', methods=['POST'])
@jwt_required()
def add_ordenes():
    current_user_id = get_jwt_identity() 
    body = request.get_json()
    orden = Ordenes()
    orden.user_id = current_user_id
    orden.service_id = body['service_id']
    orden.event_date = body['event_date']
    orden.event_address = body['event_address']

    db.session.add(orden) # agrega el favorito a la base de datos
    db.session.commit() # guarda los cambios

    user_orden = Ordenes.query.filter_by(user_id=current_user_id)
    user_orden = list(map(lambda x: x.serialize(), user_orden))

    return jsonify(user_orden), 200