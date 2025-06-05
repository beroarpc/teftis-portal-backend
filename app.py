from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'gizli-anahtar-buraya'  
jwt = JWTManager(app)

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if username == "admin" and password == "1234":
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"message": "Geçersiz kullanıcı adı veya şifre"}), 401

@app.route('/dashboard-data', methods=['GET'])
def dashboard_data():
    return jsonify({
        "karsilama": "Hoş geldiniz, sayın başkanım.",
        "denetim_sayisi": 12,
        "aktif_soruşturma": 4
    })
@jwt_required()
def dashboard_data():
    return jsonify({"message": "Dashboard verisi"}), 200

if __name__ == '__main__':
    app.run(debug=True)
