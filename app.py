from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if username == "admin" and password == "1234":
        return jsonify({"message": "Giriş başarılı"}), 200
    else:
        return jsonify({"message": "Geçersiz kullanıcı adı veya şifre"}), 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
