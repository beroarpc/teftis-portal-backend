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

frontend_url = "https://teftis-portal-frontend-5u7j.vercel.app"
CORS(app, resources={r"/*": {"origins": frontend_url}}, supports_credentials=True)

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

class Sorusturma(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sorusturma_no = db.Column(db.String(100), unique=True, nullable=False)
    konu = db.Column(db.Text, nullable=False)
    olusturma_tarihi = db.Column(db.DateTime, server_default=db.func.now())
    durum = db.Column(db.String(50), default='Açık')
    onay_durumu = db.Column(db.String(50), nullable=False, default='Onay Bekliyor')
    atanan_mufettis_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    atanan_mufettis = db.relationship('User', backref=db.backref('sorusturmalar', lazy=True))
    dosyalar = db.relationship('Dosya', backref='sorusturma', lazy=True, cascade="all, delete-orphan")

class Dosya(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dosya_adi = db.Column(db.String(200), nullable=False)
    dosya_url = db.Column(db.String(500), nullable=False)
    public_id = db.Column(db.String(200), nullable=False)
    yukleme_tarihi = db.Column(db.DateTime, server_default=db.func.now())
    sorusturma_id = db.Column(db.Integer, db.ForeignKey('sorusturma.id'), nullable=False)


@app.route('/api/sorusturmalar/<int:sorusturma_id>', methods=['GET'])
@jwt_required()
def get_sorusturma_detay(sorusturma_id):
    sorusturma = Sorusturma.query.get(sorusturma_id)
    if not sorusturma:
        return jsonify(message="Soruşturma bulunamadı"), 404
    
    dosyalar_listesi = [{'id': dosya.id, 'dosya_adi': dosya.dosya_adi, 'dosya_url': dosya.dosya_url} for dosya in sorusturma.dosyalar]
    
    atanan_mufettis_adi = sorusturma.atanan_mufettis.username if sorusturma.atanan_mufettis else None

    sonuc = {
        'id': sorusturma.id,
        'sorusturma_no': sorusturma.sorusturma_no,
        'konu': sorusturma.konu,
        'olusturma_tarihi': sorusturma.olusturma_tarihi.strftime('%Y-%m-%d %H:%M:%S'),
        'durum': sorusturma.durum,
        'onay_durumu': sorusturma.onay_durumu,
        'dosyalar': dosyalar_listesi,
        'atanan_mufettis': atanan_mufettis_adi # Yeni alan
    }
    return jsonify(sonuc), 200


@app.route('/api/mufettisler', methods=['GET'])
@jwt_required()
def get_mufettisler():
    mufettisler = User.query.filter_by(rol='müfettiş').all()
    sonuc = [{'id': mufettis.id, 'username': mufettis.username} for mufettis in mufettisler]
    return jsonify(sonuc), 200

@app.route('/api/sorusturmalar/<int:sorusturma_id>/ata', methods=['POST'])
@roller_gerekiyor('başkan')
def ata_mufettis(sorusturma_id):
    data = request.get_json()
    mufettis_id = data.get('mufettis_id')
    if not mufettis_id:
        return jsonify(message="Müfettiş ID'si zorunludur."), 400
    sorusturma = Sorusturma.query.get(sorusturma_id)
    mufettis = User.query.get(mufettis_id)
    if not sorusturma:
        return jsonify(message="Soruşturma bulunamadı."), 404
    if not mufettis or mufettis.rol != 'müfettiş':
        return jsonify(message="Geçerli bir müfettiş bulunamadı."), 404
    sorusturma.atanan_mufettis_id = mufettis_id
    db.session.commit()
    return jsonify(message=f"Soruşturma, {mufettis.username} adlı müfettişe başarıyla atandı."), 200
