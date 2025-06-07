from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "gizli-anahtar-buraya"
jwt = JWTManager(app)


users = {
    "admin": {"password": "1234", "role": "başkan"},
    "mufettis": {"password": "1234", "role": "müfettiş"},
    "yardimci": {"password": "1234", "role": "müfettiş yardımcısı"},
}

@app.route("/login", methods=["POST"])
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
