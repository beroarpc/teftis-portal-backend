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

frontend_url = "https://teftis-portal-frontend-mzj1.vercel.app"
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
    if not user: return jsonify(message="Token geçersiz, kullanıcı bulunamadı"), 404
    return jsonify(karsilama=f"Hoş geldiniz, sayın {user.rol.title()}", denetim_sayisi=15, aktif_soruşturma=5, rol=user.rol), 200

@app.route('/api/sorusturmalar', methods=['POST'])
@roller_gerekiyor('başkan', 'müfettiş')
def create_sorusturma():
    current_username = get_jwt_identity()
    user = User.query.filter_by(username=current_username).first()
    data = request.get_json()
    if not data or not data.get('sorusturma_no') or not data.get('konu'):
        return jsonify(message="Eksik bilgi: sorusturma_no ve konu alanları zorunludur"), 400
    onay_durumu = 'Onaylandı' if user.rol == 'başkan' else 'Onay Bekliyor'
    yeni_sorusturma = Sorusturma(sorusturma_no=data['sorusturma_no'], konu=data['konu'], durum=data.get('durum', 'Açık'), onay_durumu=onay_durumu)
    db.session.add(yeni_sorusturma)
    db.session.commit()
    return jsonify(message="Soruşturma başarıyla oluşturuldu!", id=yeni_sorusturma.id), 201

@app.route('/api/sorusturmalar', methods=['GET'])
@jwt_required()
def get_sorusturmalar():
    sorusturmalar_listesi = Sorusturma.query.order_by(Sorusturma.olusturma_tarihi.desc()).all()
    sonuc = []
    for sorusturma in sorusturmalar_listesi:
        sonuc.append({'id': sorusturma.id, 'sorusturma_no': sorusturma.sorusturma_no, 'konu': sorusturma.konu, 'olusturma_tarihi': sorusturma.olusturma_tarihi.strftime('%Y-%m-%d %H:%M:%S'), 'durum': sorusturma.durum, 'onay_durumu': sorusturma.onay_durumu})
    return jsonify(sonuc), 200

@app.route('/api/sorusturmalar/<int:sorusturma_id>', methods=['GET'])
@jwt_required()
def get_sorusturma_detay(sorusturma_id):
    sorusturma = Sorusturma.query.get(sorusturma_id)
    if not sorusturma:
        return jsonify(message="Soruşturma bulunamadı"), 404
    dosyalar_listesi = []
    for dosya in sorusturma.dosyalar:
        dosyalar_listesi.append({'id': dosya.id, 'dosya_adi': dosya.dosya_adi, 'dosya_url': dosya.dosya_url})
    sonuc = {'id': sorusturma.id, 'sorusturma_no': sorusturma.sorusturma_no, 'konu': sorusturma.konu, 'olusturma_tarihi': sorusturma.olusturma_tarihi.strftime('%Y-%m-%d %H:%M:%S'), 'durum': sorusturma.durum, 'onay_durumu': sorusturma.onay_durumu, 'dosyalar': dosyalar_listesi}
    return jsonify(sonuc), 200

@app.route('/api/sorusturmalar/<int:sorusturma_id>/onayla', methods=['POST'])
@roller_gerekiyor('başkan')
def onayla_sorusturma(sorusturma_id):
    sorusturma = Sorusturma.query.get(sorusturma_id)
    if not sorusturma: return jsonify(message="Soruşturma bulunamadı"), 404
    sorusturma.onay_durumu = 'Onaylandı'
    db.session.commit()
    return jsonify(message="Soruşturma başarıyla onaylandı."), 200

@app.route('/api/sorusturmalar/<int:sorusturma_id>/upload', methods=['POST'])
@jwt_required()
def upload_file(sorusturma_id):
    if 'file' not in request.files: return jsonify(message='Dosya bulunamadı'), 400
    file = request.files['file']
    if file.filename == '': return jsonify(message='Dosya seçilmedi'), 400
    sorusturma = Sorusturma.query.get(sorusturma_id)
    if not sorusturma: return jsonify(message='İlişkili soruşturma bulunamadı'), 404
    try:
        filename = secure_filename(file.filename)
        upload_result = cloudinary.uploader.upload(file, folder=f"sorusturmalar/{sorusturma.id}", resource_type="auto")
        yeni_dosya = Dosya(dosya_adi=filename, dosya_url=upload_result['secure_url'], public_id=upload_result['public_id'], sorusturma_id=sorusturma.id)
        db.session.add(yeni_dosya)
        db.session.commit()
        return jsonify(message='Dosya başarıyla yüklendi', file_url=upload_result['secure_url']), 201
    except Exception as e:
        return jsonify(message=f'Dosya yüklenirken bir hata oluştu: {str(e)}'), 500

@app.route('/init-db-and-users')
def init_db():
    with app.app_context():
        try:
            db.create_all()
            if User.query.filter_by(username='admin').first() is None:
                db.session.add(User(username='admin', rol='başkan', password_hash=generate_password_hash('1234')))
            if User.query.filter_by(username='mufettis').first() is None:
                db.session.add(User(username='mufettis', rol='müfettiş', password_hash=generate_password_hash('1234')))
            if User.query.filter_by(username='mufettis_yardimcisi').first() is None:
                db.session.add(User(username='mufettis_yardimcisi', rol='müfettiş yardımcısı', password_hash=generate_password_hash('1234')))
            db.session.commit()
            return "Veritabanı tabloları başarıyla oluşturuldu/güncellendi!"
        except Exception as e:
            return f"Bir hata oluştu: {str(e)}"

if __name__ == "__main__":
    app.run(debug=True)