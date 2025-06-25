import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request
)
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import cloudinary
import cloudinary.uploader
from werkzeug.utils import secure_filename
from datetime import datetime

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'default-guvensiz-anahtar')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

cloudinary.config(
    cloud_name=os.environ.get('CLOUDINARY_CLOUD_NAME'),
    api_key=os.environ.get('CLOUDINARY_API_KEY'),
    api_secret=os.environ.get('CLOUDINARY_API_SECRET')
)

db = SQLAlchemy(app)
jwt = JWTManager(app)

origins = [
    "https://teftis-portal-frontend.vercel.app",
    "https://teftis-portal-frontend-mzj1.vercel.app",
    "https://teftis-portal-frontend-5u7j.vercel.app",
    "http://localhost:3000"
]
CORS(app, resources={r"/*": {"origins": origins}}, supports_credentials=True)


def roller_gerekiyor(*roller):
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            current_username = get_jwt_identity()
            user = User.query.filter_by(username=current_username).first()
            if user and user.rol in roller:
                return fn(*args, **kwargs)
            else:
                return jsonify(message="Bu işlemi yapmak için yetkiniz yok!"), 403
        return decorator
    return wrapper

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    rol = db.Column(db.String(50), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Personel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sicil_no = db.Column(db.String(100), unique=True, nullable=False)
    ad = db.Column(db.String(100), nullable=False)
    soyad = db.Column(db.String(100), nullable=False)
    unvan = db.Column(db.String(150))
    sube = db.Column(db.String(150))
    ise_baslama_tarihi = db.Column(db.Date)
    aktif_mi = db.Column(db.Boolean, default=True, nullable=False)
    profil_resmi_url = db.Column(db.String(500))
    profil_resmi_pid = db.Column(db.String(200))

class Sorusturma(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sorusturma_no = db.Column(db.String(100), unique=True, nullable=False)
    konu = db.Column(db.Text, nullable=False)
    olusturma_tarihi = db.Column(db.DateTime, server_default=db.func.now())
    durum = db.Column(db.String(50), default='Açık')
    onay_durumu = db.Column(db.String(50), nullable=False, default='Onay Bekliyor')
    personel_id = db.Column(db.Integer, db.ForeignKey('personel.id'), nullable=True)
    hakkindaki_personel = db.relationship('Personel', backref=db.backref('sorusturmalar', lazy=True))
    atanan_mufettis_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    atanan_mufettis = db.relationship('User', backref=db.backref('atanan_sorusturmalar', lazy=True))
    dosyalar = db.relationship('Dosya', backref='sorusturma', lazy=True, cascade="all, delete-orphan")
    cezalar = db.relationship('Ceza', backref='sorusturma', lazy=True, cascade="all, delete-orphan")

class Dosya(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dosya_adi = db.Column(db.String(200), nullable=False)
    dosya_url = db.Column(db.String(500), nullable=False)
    public_id = db.Column(db.String(200), nullable=False)
    yukleme_tarihi = db.Column(db.DateTime, server_default=db.func.now())
    sorusturma_id = db.Column(db.Integer, db.ForeignKey('sorusturma.id'), nullable=False)

class Ceza(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ceza_turu = db.Column(db.String(150), nullable=False)
    aciklama = db.Column(db.Text, nullable=True)
    verilme_tarihi = db.Column(db.Date, nullable=False)
    sorusturma_id = db.Column(db.Integer, db.ForeignKey('sorusturma.id'), nullable=False)
    personel_id = db.Column(db.Integer, db.ForeignKey('personel.id'), nullable=False)
    alan_personel = db.relationship('Personel', backref=db.backref('cezalar', lazy=True))


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
    return jsonify({"message": "Geçersiz kullanıcı adı veya şifre"}), 401


@app.route('/api/sorusturmalar/<int:sorusturma_id>/ceza-ekle', methods=['POST'])
@roller_gerekiyor('başkan')
def add_ceza_to_sorusturma(sorusturma_id):
    sorusturma = Sorusturma.query.get(sorusturma_id)
    if not sorusturma: return jsonify(message="Soruşturma bulunamadı."), 404
    if not sorusturma.hakkindaki_personel: return jsonify(message="Bu soruşturma bir personele bağlı değil, ceza eklenemez."), 400
    data = request.get_json()
    ceza_turu = data.get('ceza_turu')
    verilme_tarihi_str = data.get('verilme_tarihi')
    aciklama = data.get('aciklama')
    if not all([ceza_turu, verilme_tarihi_str]): return jsonify(message="Ceza türü ve verilme tarihi zorunludur."), 400
    try:
        verilme_tarihi = datetime.strptime(verilme_tarihi_str, '%Y-%m-%d').date()
    except ValueError:
        return jsonify(message="Tarih formatı geçersiz. Lütfen YYYY-MM-DD formatında girin."), 400
    yeni_ceza = Ceza(ceza_turu=ceza_turu, aciklama=aciklama, verilme_tarihi=verilme_tarihi, sorusturma_id=sorusturma.id, personel_id=sorusturma.personel_id)
    db.session.add(yeni_ceza)
    db.session.commit()
    return jsonify(message="Ceza başarıyla eklendi."), 201

if __name__ == "__main__":
    app.run(debug=True)