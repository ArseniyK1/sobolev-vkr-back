from flask import Flask, request, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_migrate import Migrate
import bcrypt
import jwt

app = Flask(__name__)
CORS(app)  # Enable CORS
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres:root@localhost:5432/dima_vkr"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'pluxuryedd'  # Set your secret key for JWT
db = SQLAlchemy(app)
migrate = Migrate(app, db)

class Roles(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(100), nullable=False)
    users = db.relationship('User', backref='role', lazy=True)

    def __repr__(self):
        return '<Roles {}>'.format(self.value)

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(256), nullable=False)
    last_name = db.Column(db.String(256), nullable=False)
    middle_name = db.Column(db.String(256), nullable=False)
    login = db.Column(db.String(256), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=False)

    def __repr__(self):
        return '<User {}>'.format(self.login)

    def serialize(self):
        return {
            'id': self.id,
            'login': self.login,
            'role': self.role.value if self.role else None
        }


with app.app_context():
    try:
        db.create_all()
        print("Tables created successfully.")
    except Exception as e:
        print("Failed to create tables.")
        print(str(e))


@app.route("/user/register", methods=['POST'])
def register():
    data = request.get_json()
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    middle_name = data.get('middle_name')
    login = data.get('login')
    raw_password = data.get('password')

    # Hash the password
    hashed_password = bcrypt.hashpw(raw_password.encode('utf-8'), bcrypt.gensalt())

    # Create the user
    user = User(first_name=first_name, last_name=last_name, middle_name=middle_name,
                login=login, password=hashed_password.decode('utf-8'), role_id=1)

    try:
        db.session.add(user)
        db.session.commit()
        return jsonify({'message': 'User created successfully'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route("/auth/login", methods=['POST'])
def login():
    data = request.get_json()
    login = data.get('login')
    password = data.get('password')

    # Find user by login
    user = User.query.filter_by(login=login).first()
    if not user:
        return jsonify({'error': 'Invalid login credentials'}), 401

    # Check password
    if bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        # Generate JWT token
        token = jwt.encode({'user_id': user.id}, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': token}), 200
    else:
        return jsonify({'error': 'Invalid login credentials'}), 401

@app.route("/auth/profile", methods=['GET'])
def profile():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'error': 'Authorization header is missing'}), 401

    token = auth_header.split(' ')[1]  # Bearer token_value
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
        user = User.query.filter_by(id=user_id).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Include role information using left join
        user_with_role = User.query.filter_by(id=user_id).join(Roles).first()
        if not user_with_role:
            return jsonify({'error': 'User role not found'}), 404

        return jsonify(user_with_role.serialize()), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token is expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401

if __name__ == "__main__":
    app.run(debug=True)
