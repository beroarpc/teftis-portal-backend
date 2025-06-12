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

class Dosya(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dosya_adi = db.Column(db.String(200), nullable=False)
    dosya_url = db.Column(db.String(500), nullable=False)
    public_id = db.Column(db.String(200), nullable=False)
    yukleme_tarihi = db.Column(db.DateTime, server_default=db.func.now())
    sorusturma_id = db.Column(db.Integer, db.ForeignKey('sorusturma.id'), nullable=False)

class Personel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sicil_no = db.Column(db.String(100), unique=True, nullable=False)
    ad = db.Column(db.String(100), nullable=False)
    soyad = db.Column(db.String(100), nullable=False)
    unvan = db.Column(db.String(150))
    ise_baslama_tarihi = db.Column(db.Date)
    aktif_mi = db.Column(db.Boolean, default=True, nullable=False)

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
    data = request.get_json()
    if not data or not data.get('sorusturma_no') or not data.get('konu'):
        return jsonify(message="Eksik bilgi: sorusturma_no ve konu alanları zorunludur"), 400
    current_username = get_jwt_identity()
    user = User.query.filter_by(username=current_username).first()
    onay_durumu = 'Onaylandı' if user.rol == 'başkan' else 'Onay Bekliyor'
    yeni_sorusturma = Sorusturma(sorusturma_no=data['sorusturma_no'], konu=data['konu'], durum=data.get('durum', 'Açık'), onay_durumu=onay_durumu, personel_id=data.get('personel_id'))
    db.session.add(yeni_sorusturma)
    db.session.commit()
    return jsonify(message="Soruşturma başarıyla oluşturuldu!", id=yeni_sorusturma.id), 201

@app.route('/api/sorusturmalar', methods=['GET'])
@jwt_required()
def get_sorusturmalar():
    sorusturmalar_listesi = Sorusturma.query.order_by(Sorusturma.olusturma_tarihi.desc()).all()
    sonuc = []
    for sorusturma in sorusturmalar_listesi:
        personel_adi = f"{sorusturma.hakkindaki_personel.ad} {sorusturma.hakkindaki_personel.soyad}" if sorusturma.hakkindaki_personel else "Belirtilmemiş"
        sonuc.append({'id': sorusturma.id, 'sorusturma_no': sorusturma.sorusturma_no, 'konu': sorusturma.konu, 'olusturma_tarihi': sorusturma.olusturma_tarihi.strftime('%Y-%m-%d %H:%M:%S'), 'durum': sorusturma.durum, 'onay_durumu': sorusturma.onay_durumu, 'hakkindaki_personel': personel_adi})
    return jsonify(sonuc), 200

@app.route('/api/sorusturmalar/<int:sorusturma_id>', methods=['GET'])
@jwt_required()
def get_sorusturma_detay(sorusturma_id):
    sorusturma = Sorusturma.query.get(sorusturma_id)
    if not sorusturma:
        return jsonify(message="Soruşturma bulunamadı"), 404
    dosyalar_listesi = [{'id': dosya.id, 'dosya_adi': dosya.dosya_adi, 'dosya_url': dosya.dosya_url} for dosya in sorusturma.dosyalar]
    atanan_mufettis_adi = sorusturma.atanan_mufettis.username if sorusturma.atanan_mufettis else None
    personel_adi = f"{sorusturma.hakkindaki_personel.ad} {sorusturma.hakkindaki_personel.soyad}" if sorusturma.hakkindaki_personel else "Belirtilmemiş"
    sonuc = {'id': sorusturma.id, 'sorusturma_no': sorusturma.sorusturma_no, 'konu': sorusturma.konu, 'olusturma_tarihi': sorusturma.olusturma_tarihi.strftime('%Y-%m-%d %H:%M:%S'), 'durum': sorusturma.durum, 'onay_durumu': sorusturma.onay_durumu, 'dosyalar': dosyalar_listesi, 'atanan_mufettis': atanan_mufettis_adi, 'hakkindaki_personel': personel_adi}
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

@app.route('/api/mufettisler', methods=['GET'])
@jwt_required()
def get_mufettisler():
    try:
        mufettisler = User.query.filter_by(rol='müfettiş').all()
        sonuc = [{'id': mufettis.id, 'username': mufettis.username} for mufettis in mufettisler]
        return jsonify(sonuc), 200
    except Exception as e:
        return jsonify(message=f"Sunucuda bir hata oluştu: {str(e)}"), 500

@app.route('/api/sorusturmalar/<int:sorusturma_id>/ata', methods=['POST'])
@roller_gerekiyor('başkan')
def ata_mufettis(sorusturma_id):
    data = request.get_json()
    mufettis_id = data.get('mufettis_id')
    if not mufettis_id:
        return jsonify(message="Müfettiş ID'si zorunludur."), 400
    sorusturma = Sorusturma.query.get(sorusturma_id)
    mufettis = User.query.get(mufettis_id)
    if not sorusturma: return jsonify(message="Soruşturma bulunamadı."), 404
    if not mufettis or mufettis.rol != 'müfettiş': return jsonify(message="Geçerli bir müfettiş bulunamadı."), 404
    sorusturma.atanan_mufettis_id = mufettis_id
    db.session.commit()
    return jsonify(message=f"Soruşturma, {mufettis.username} adlı müfettişe başarıyla atandı."), 200

@app.route('/api/personel', methods=['POST'])
@roller_gerekiyor('başkan')
def create_personel():
    data = request.get_json()
    if not data or not data.get('sicil_no') or not data.get('ad') or not data.get('soyad'):
        return jsonify(message="Sicil No, Ad ve Soyad alanları zorunludur"), 400
    yeni_personel = Personel(sicil_no=data['sicil_no'], ad=data['ad'], soyad=data['soyad'], unvan=data.get('unvan'))
    db.session.add(yeni_personel)
    db.session.commit()
    return jsonify(message="Personel başarıyla eklendi."), 201

@app.route('/api/personel', methods=['GET'])
@jwt_required()
def get_personel_listesi():
    personeller = Personel.query.all()
    sonuc = []
    for p in personeller:
        sonuc.append({'id': p.id, 'sicil_no': p.sicil_no, 'ad': p.ad, 'soyad': p.soyad, 'unvan': p.unvan, 'aktif_mi': p.aktif_mi})
    return jsonify(sonuc), 200

@app.route('/api/personel/<int:personel_id>', methods=['PUT'])
@roller_gerekiyor('başkan')
def update_personel(personel_id):
    personel = Personel.query.get(personel_id)
    if not personel: return jsonify(message="Personel bulunamadı"), 404
    data = request.get_json()
    personel.sicil_no = data.get('sicil_no', personel.sicil_no)
    personel.ad = data.get('ad', personel.ad)
    personel.soyad = data.get('soyad', personel.soyad)
    personel.unvan = data.get('unvan', personel.unvan)
    personel.aktif_mi = data.get('aktif_mi', personel.aktif_mi)
    db.session.commit()
    return jsonify(message="Personel bilgileri güncellendi."), 200

@app.route('/api/personel/<int:personel_id>', methods=['DELETE'])
@roller_gerekiyor('başkan')
def delete_personel(personel_id):
    personel = Personel.query.get(personel_id)
    if not personel: return jsonify(message="Personel bulunamadı"), 404
    personel.aktif_mi = False
    db.session.commit()
    return jsonify(message="Personel kaydı pasif hale getirildi."), 200

@app.route('/api/rapor', methods=['GET'])
@jwt_required()
def get_report():
    personel_id = request.args.get('personel_id', type=int)
    baslangic_tarihi_str = request.args.get('baslangic')
    bitis_tarihi_str = request.args.get('bitis')
    query = Sorusturma.query
    if personel_id:
        query = query.filter(Sorusturma.personel_id == personel_id)
    if baslangic_tarihi_str:
        baslangic_tarihi = datetime.strptime(baslangic_tarihi_str, '%Y-%m-%d')
        query = query.filter(Sorusturma.olusturma_tarihi >= baslangic_tarihi)
    if bitis_tarihi_str:
        bitis_tarihi = datetime.strptime(bitis_tarihi_str, '%Y-%m-%d')
        query = query.filter(Sorusturma.olusturma_tarihi <= bitis_tarihi.replace(hour=23, minute=59, second=59))
    sorusturmalar_listesi = query.order_by(Sorusturma.olusturma_tarihi.desc()).all()
    sonuc = []
    for sorusturma in sorusturmalar_listesi:
        personel_adi = f"{sorusturma.hakkindaki_personel.ad} {sorusturma.hakkindaki_personel.soyad}" if sorusturma.hakkindaki_personel else "Belirtilmemiş"
        sonuc.append({'id': sorusturma.id, 'sorusturma_no': sorusturma.sorusturma_no, 'konu': sorusturma.konu, 'olusturma_tarihi': sorusturma.olusturma_tarihi.strftime('%Y-%m-%d %H:%M:%S'), 'durum': sorusturma.durum, 'onay_durumu': sorusturma.onay_durumu, 'hakkindaki_personel': personel_adi})
    return jsonify(sonuc), 200
    
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