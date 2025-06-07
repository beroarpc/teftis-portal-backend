import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'default-guvensiz-anahtar')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
jwt = JWTManager(app)

frontend_url = "https://teftis-portal-frontend-5u7j.vercel.app"
CORS(app, resources={r"/*": {"origins": frontend_url}}, supports_credentials=True)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    rol = db.Column(db.String(50), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Sorusturma(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sorusturma_no = db.Column(db.String(100), unique=True, nullable=False)
    konu = db.Column(db.Text, nullable=False)
    olusturma_tarihi = db.Column(db.DateTime, server_default=db.func.now())
    durum = db.Column(db.String(50), default='Açık')
    atanan_mufettis_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    atanan_mufettis = db.relationship('User', backref=db.backref('sorusturmalar', lazy=True))

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"message": "Geçersiz kullanıcı adı veya şifre"}), 401

@app.route('/dashboard-data', methods=['GET'])
@jwt_required()
def dashboard_data():
    current_username = get_jwt_identity()
    user = User.query.filter_by(username=current_username).first()
    if not user:
        return jsonify({"message": "Token geçersiz, kullanıcı bulunamadı"}), 404
    return jsonify({
        "karsilama": f"Hoş geldiniz, sayın {user.rol.title()}",
        "denetim_sayisi": 15,
        "aktif_soruşturma": 5,
        "rol": user.rol
    }), 200

@app.route('/api/sorusturmalar', methods=['POST'])
@jwt_required()
def create_sorusturma():
    data = request.get_json()
    if not data or not data.get('sorusturma_no') or not data.get('konu'):
        return jsonify({"message": "Eksik bilgi: sorusturma_no ve konu alanları zorunludur"}), 400
    yeni_sorusturma = Sorusturma(
        sorusturma_no=data['sorusturma_no'],
        konu=data['konu'],
        durum=data.get('durum', 'Açık')
    )
    db.session.add(yeni_sorusturma)
    db.session.commit()
    return jsonify({"message": "Soruşturma başarıyla oluşturuldu!", "id": yeni_sorusturma.id}), 201

@app.route('/api/sorusturmalar', methods=['GET'])
@jwt_required()
def get_sorusturmalar():
    sorusturmalar_listesi = Sorusturma.query.order_by(Sorusturma.olusturma_tarihi.desc()).all()
    sonuc = []
    for sorusturma in sorusturmalar_listesi:
        sonuc.append({
            'id': sorusturma.id,
            'sorusturma_no': sorusturma.sorusturma_no,
            'konu': sorusturma.konu,
            'olusturma_tarihi': sorusturma.olusturma_tarihi.strftime('%Y-%m-%d %H:%M:%S'),
            'durum': sorusturma.durum
        })
    return jsonify(sonuc), 200

@app.route('/init-db-and-users')
def init_db():
    with app.app_context():
        try:
            db.create_all()
            if User.query.filter_by(username='admin').first() is None:
                admin_user = User(username='admin', rol='başkan')
                admin_user.set_password('1234')
                db.session.add(admin_user)
            if User.query.filter_by(username='mufettis').first() is None:
                mufettis_user = User(username='mufettis', rol='müfettiş')
                mufettis_user.set_password('1234')
                db.session.add(mufettis_user)
            db.session.commit()
            return "Veritabanı (sadece User tablosu) başarıyla kuruldu!"
        except Exception as e:
            return f"Bir hata oluştu: {str(e)}"

if __name__ == "__main__":
    app.run(debug=True)