from flask import Flask, request, jsonify
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from flask_cors import CORS

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'gizli-anahtar-buraya'
CORS(app, supports_credentials=True)  

jwt = JWTManager(app)


users = {
    "admin": {"password": "1234", "rol": "başkan"},
    "mufettis": {"password": "1234", "rol": "müfettiş"},
    "mufettis_yardimcisi": {"password": "1234", "rol": "müfettiş yardımcısı"}
}

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    user = users.get(username)

    if user and user["password"] == password:
        access_token = create_access_token(identity={"username": username, "rol": user["rol"]})
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"message": "Geçersiz kullanıcı adı veya şifre"}), 401

@app.route('/dashboard-data', methods=['GET'])
@jwt_required()
def dashboard_data():
    try:
        current_user = get_jwt_identity()
        print("Aktif kullanıcı:", current_user)  
        return jsonify({
            "karsilama": f"Hoş geldiniz, sayın {current_user['rol']}.",
            "denetim_sayisi": 12,
            "aktif_soruşturma": 4,
            "rol": current_user['rol']
        }), 200
    except Exception as e:
        print("Hata:", e)  # LOG: hatayı gör
        return jsonify({"error": str(e)}), 401

if __name__ == "__main__":
    app.run(debug=True)
