from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity
)
from flask_cors import CORS
import datetime
from flask_jwt_extended import verify_jwt_in_request, get_jwt
from flask_jwt_extended import get_jti
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DB_URL")
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'  
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(minutes=30)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = datetime.timedelta(hours=24)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app, resources={r"/*":{"origins": ["http://localhost:5173","https://bulc.netlify.app"]}},supports_credentials=True)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default="user")
    email = db.Column(db.String(120), unique=True, nullable=False)  
    matric_num = db.Column(db.String(20), unique=True, nullable=True)
    level = db.Column(db.String(20), nullable=True)
    department = db.Column(db.String(50), nullable=True)
    class_group = db.Column(db.String(50), nullable=True)
    
class TokenBlocklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False)  
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    revoked = db.Column(db.Boolean, default=False)
    expires_at = db.Column(db.DateTime, nullable=False) 


with app.app_context():
    db.create_all()
    admin = User.query.filter_by(role="admin").first()
    if not admin:
            hashed_pw = bcrypt.generate_password_hash("@Golden_bird5").decode('utf-8')
            new_admin = User(username="Admin", role="admin", password=hashed_pw , email="nolimitblaqs@gmail.com")
            db.session.add(new_admin)
            db.session.commit()
            print("✅ Admin created (username='Admin')")


@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    email = data.get("email")
    matric_num = data.get("matric_num")
    level = data.get("level")
    department = data.get("department")
    class_group = data.get("class_group")
    
    
    if not username or not password:
        return jsonify({"msg": "Missing username or password"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"msg": "Username already exists"}), 409
    
    

    hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, password=hashed_pw, role="user" , email=email, matric_num=matric_num, level=level, department=department, class_group=class_group)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"msg": "User created successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"msg": "Missing username or password"}), 400

    user = User.query.filter_by(username=username).first()
    if user and bcrypt.check_password_hash(user.password, password):
        access_token = create_access_token(identity=str(user.id), additional_claims={"role": user.role})
        refresh_token = create_refresh_token(identity=str(user.id))
        expires_at = datetime.datetime.now(datetime.timezone.utc) + app.config['JWT_ACCESS_TOKEN_EXPIRES']

        jti = get_jti(encoded_token=access_token)
        db.session.add(TokenBlocklist(
            jti=jti,
            user_id=user.id,
            revoked=False,
            expires_at=expires_at
        ))
        db.session.commit()

        return jsonify({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "username": user.username,
            "role": user.role,
        }), 200

    return jsonify({"msg": "Invalid username or password"}), 401

@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()["jti"]
    token = TokenBlocklist.query.filter_by(jti=jti).first()
    if token:
        token.revoked = True
        db.session.commit()
    return jsonify(msg="Successfully logged out"), 200


@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user_id = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user_id)
    return jsonify(access_token=new_access_token), 200


@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    return jsonify({"msg": f"Hello, {user.username}!"}), 200

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    token = TokenBlocklist.query.filter_by(jti=jti, revoked=True).first()
    return token is not None

@app.route('/admin/users', methods=['GET'])
@jwt_required()
def get_all_users():
    claims = get_jwt()
    if claims.get("role") != "admin":
        return jsonify({"msg": "Admins only!"}), 403

    users = User.query.all()
    user_list = []

    for u in users:
        active_token = TokenBlocklist.query.filter(
        TokenBlocklist.user_id == u.id,
        TokenBlocklist.revoked == False,
        TokenBlocklist.expires_at > datetime.datetime.utcnow()
        ).first() is not None

        user_list.append({
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "matric_num": u.matric_num,
            "level": u.level,
            "department": u.department,
            "class_group": u.class_group,
            "role": u.role,
            "active_token": active_token
        })


    return jsonify(user_list), 200


if __name__ == '__main__':
    app.run(debug=True)

