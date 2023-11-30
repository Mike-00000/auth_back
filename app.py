from datetime import datetime
import time

print("Heure actuelle UTC:", datetime.utcnow())
print("Fuseau horaire système:", time.tzname)


from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
# config data from config.py
from config import Config
# migrate
from flask_migrate import Migrate

from datetime import datetime
from sqlalchemy import DateTime

# create the app
app = Flask(__name__)
CORS(app, origins="http://localhost:3000", 
     methods=["GET", "POST", "DELETE", "PUT", "OPTIONS"], 
     allow_headers=["Authorization", "Content-Type"], 
     supports_credentials=True)

# CORS(app, origins="*", methods=["GET", "POST", "DELETE", "PUT", "OPTIONS"], allow_headers=["Authorization", "Content-Type"], supports_credentials=True)
# CORS(app, resources={r"/api/*": {"origins": "*"}})

jwt = JWTManager(app)

# from config file
app.config.from_object(Config)

app.config['SQLALCHEMY_DATABASE_URI']
app.config['JWT_SECRET_KEY'] 
# disables a feature that automatically tracks modifications to objects and emits signals 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']

# this variable, db, will be used for all SQLAlchemy commands
db = SQLAlchemy(app)

migrate = Migrate(app, db)

jwt = JWTManager(app)

members_association_table = db.Table('members',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('organization_id', db.Integer, db.ForeignKey('organization.id'), primary_key=True)
)
# class represent a table in database
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(1000), nullable=False) 
    role = db.Column(db.String(50), default='user')
    date_created = db.Column(DateTime, default=datetime.utcnow)
    last_login = db.Column(DateTime, nullable=True)
    organizations = db.relationship('Organization', secondary=members_association_table, back_populates='members')

class Organization(db.Model): 
    id = db.Column(db.Integer, primary_key=True) 
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.String(255))
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    status = db.Column(db.String(50), default='active')
    country = db.Column(db.String(100))
    members = db.relationship('User', secondary=members_association_table, back_populates='organizations')

import re

def validate_email(email):
    regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(regex, email) is not None

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()

    if not validate_email(data.get('email', '')):
        return jsonify({"message": "Invalid email format!"}), 400
    
    if User.query.filter_by(email=data['email']).first() is not None:
        return jsonify({"message": "Email already exists!"}), 400
    
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(email=data['email'], password=hashed_password, first_name=first_name, last_name=last_name)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User created!"}), 201

@app.route('/signin', methods=['POST'])
def signin():
    data = request.get_json()
    print("Requête reçue pour /signin avec les données :", data)
    user = User.query.filter_by(email=data['email']).first()  # Modified here
    # tests log
    print("Req data =>", data)
    print("DB query user", user)
    print(app.config['JWT_ACCESS_TOKEN_EXPIRES'])

    
    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({"message": "Invalid credentials!"}), 401
    
    user.last_login = datetime.utcnow()
    db.session.commit()

    access_token = create_access_token(identity=user.email) 
    return jsonify({"access_token": access_token, "firstName": user.first_name, "lastName": user.last_name})


@app.route('/user-info', methods=['GET'])
@jwt_required()
def user_info():
    current_user_email = get_jwt_identity()
    print("Identité JWT (Email) :", current_user_email)
    print("En-tête d'Authorization :", request.headers.get('Authorization'))

    # Pour débogage: Imprimer l'en-tête d'Authorization
    print("En-tête d'Authorization :", request.headers.get('Authorization'))

    user = User.query.filter_by(email=current_user_email).first()

    if not user:
        print("Utilisateur non trouvé pour l'email :", current_user_email)
        return jsonify({"message": "User not found"}), 404

    user_data = {
        "firstName": user.first_name,
        "lastName": user.last_name,
        # Ajoutez d'autres champs si nécessaire
    }

    print("Données de l'utilisateur :", user_data)
    return jsonify(user_data), 200


@app.route('/create-org', methods=['POST'])
@jwt_required()
def create_org():
    data = request.get_json()
    current_user_id = get_jwt_identity() 

    if Organization.query.filter_by(name=data['name']).first():
        return jsonify({"message": "This organization already exists"}), 400

    new_org = Organization(
        name=data['name'],
        description=data.get('description', ''),
        country=data.get('country'),
        creator_id=current_user_id
    )
    db.session.add(new_org)
    db.session.commit()

    return jsonify({"message": "Organization successfully created"}), 201

@app.route('/add-user-to-org', methods=['POST'])
def add_user_to_org():
    data = request.get_json()
    user = User.query.filter_by(email=data['user_email']).first()
    organization = Organization.query.filter_by(name=data['org_name']).first()

    if not user or not organization:
        return jsonify({"message": "User or organization not found"}), 404

    # Ajouter l'utilisateur à l'organisation
    organization.members.append(user)
    db.session.commit()

    return jsonify({"message": "User successfully added to the organization"}), 201



@app.route('/dashboard', methods=['GET'])
@jwt_required()
def dashboard():
    # current_user_id = get_jwt_identity()  # Récupère l'identifiant de l'utilisateur connecté
    # user = User.query.get(current_user_id)  # Récupérez les informations de l'utilisateur de la base de données
    current_user_email = get_jwt_identity()
    user = User.query.filter_by(email=current_user_email).first()  # Query by email


    if not user:
        return jsonify({"message": "User not found"}), 404

    # Exemple de données à envoyer
    user_data = {
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "organizations": [
            {
                "name": org.name,
                "description": org.description,
                "date_created": org.date_created.strftime("%Y-%m-%d %H:%M:%S")  # Formatage de la date
            }
            for org in user.organizations
        ]

    }

    return jsonify(user_data), 200

if __name__ == '__main__':
    app.run(debug=True)