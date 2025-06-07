from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'gizli-anahtar-buraya'
jwt = JWTManager(app)
CORS(app)


users = {
    "admin": {"password": "1234", "role": "başkan"},
    "mufettis": {"password": "1234", "role": "müfettiş"},
    "mufettis_yardimcisi": {"password": "1234", "role": "müfettiş yardımcısı"},
}

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    user = users.get(username)

    if user and user["password"] == password:
        access_token = create_access_token(identity={"username": username, "role": user["role"]})
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"message": "Geçersiz kullanıcı adı veya şifre"}), 401

@app.route('/dashboard-data', methods=['GET'])
@jwt_required()
def dashboard_data():
    current_user = get_jwt_identity()
    return jsonify({
        "karsilama": f"Hoş geldiniz, sayın {current_user['role']}.",
        "denetim_sayisi": 12,
        "aktif_soruşturma": 4
    })
