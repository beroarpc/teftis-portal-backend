from flask import Flask, request, jsonify
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from flask_cors import CORS

app = Flask(__name__)

app.config['JWT_SECRET_KEY'] = 'sizin-cok-gizli-guvenli-anahtariniz-burada-olmalı' 

CORS(app, 
     resources={r"/*": {"origins": "*"}}, 
     headers=['Content-Type', 'Authorization'], 
     supports_credentials=True)

jwt = JWTManager(app)

users = {
    "admin": {"password": "1234", "rol": "başkan"},
    "mufettis": {"password": "1234", "rol": "müfettiş"},
    "mufettis_yardimcisi": {"password": "1234", "rol": "müfettiş yardımcısı"}
}

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data:
        return jsonify({"message": "JSON veri gönderilmedi"}), 400

    username = data.get("username")
    password = data.get("password")

    user_data = users.get(username)

    if user_data and user_data["password"] == password:
        identity_data = {"username": username, "rol": user_data["rol"]}
        access_token = create_access_token(identity=identity_data)
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"message": "Geçersiz kullanıcı adı veya şifre"}), 401

@app.route('/dashboard-data', methods=['GET'])
@jwt_required()  
def dashboard_data():
    try:

        current_user = get_jwt_identity()
        
       
        print(f"Yetkili istek alındı. Kullanıcı: {current_user}")
        
    
        return jsonify({
            "karsilama": f"Hoş geldiniz, sayın {current_user.get('rol', 'kullanıcı').title()}",
            "denetim_sayisi": 12,
            "aktif_soruşturma": 4,
            "rol": current_user.get('rol')
        }), 200
    except Exception as e:
        
        print(f"Dashboard verisi gönderilirken bir hata oluştu: {e}")
        return jsonify({"message": "Sunucu hatası"}), 500


if __name__ == "__main__":
 
    app.run(debug=True, port=5000)