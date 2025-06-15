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

origins = [
    "https://teftis-portal-frontend.vercel.app",
    "https://teftis-portal-frontend-mzj1.vercel.app", # Eski adresler de kalsın
    "https://teftis-portal-frontend-5u7j.vercel.app", # Eski adresler de kalsın
    "http://localhost:3000"
]
CORS(app, resources={r"/api/*": {"origins": origins}, r"/login": {"origins": origins}, r"/dashboard-data": {"origins": origins}}, supports_credentials=True)


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
    sube_birim = db.Column(db.String(150)) # 'sube' alanı 'sube_birim' olarak güncellendi
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

@app.route('/api/personel', methods=['POST'])
@roller_gerekiyor('başkan')
def create_personel():
    if 'sicil_no' not in request.form or 'ad' not in request.form or 'soyad' not in request.form:
        return jsonify(message="Sicil No, Ad ve Soyad alanları zorunludur"), 400
    yeni_personel = Personel(
        sicil_no=request.form['sicil_no'],
        ad=request.form['ad'],
        soyad=request.form['soyad'],
        unvan=request.form.get('unvan'),
        sube_birim=request.form.get('sube_birim') # 'sube' yerine 'sube_birim'
    )
    if 'profil_resmi' in request.files:
        file = request.files['profil_resmi']
        if file.filename != '':
            try:
                upload_result = cloudinary.uploader.upload(file, folder="profil_resimleri")
                yeni_personel.profil_resmi_url = upload_result['secure_url']
                yeni_personel.profil_resmi_pid = upload_result['public_id']
            except Exception as e:
                return jsonify(message=f"Profil resmi yüklenirken hata oluştu: {str(e)}"), 500
    db.session.add(yeni_personel)
    db.session.commit()
    return jsonify(message="Personel başarıyla eklendi."), 201

@app.route('/api/personel/<int:personel_id>', methods=['PUT'])
@roller_gerekiyor('başkan')
def update_personel(personel_id):
    personel = Personel.query.get(personel_id)
    if not personel: return jsonify(message="Personel bulunamadı"), 404
    personel.sicil_no = request.form.get('sicil_no', personel.sicil_no)
    personel.ad = request.form.get('ad', personel.ad)
    personel.soyad = request.form.get('soyad', personel.soyad)
    personel.unvan = request.form.get('unvan', personel.unvan)
    personel.sube_birim = request.form.get('sube_birim', personel.sube_birim) # 'sube' yerine 'sube_birim'
    personel.aktif_mi = request.form.get('aktif_mi', personel.aktif_mi, type=lambda v: v.lower() == 'true')
    
    if 'profil_resmi' in request.files:
        file = request.files['profil_resmi']
        if file.filename != '':
            try:
                upload_result = cloudinary.uploader.upload(file, folder="profil_resimleri")
                personel.profil_resmi_url = upload_result['secure_url']
                personel.profil_resmi_pid = upload_result['public_id']
            except Exception as e:
                return jsonify(message=f"Profil resmi güncellenirken hata oluştu: {str(e)}"), 500
    
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
    if personel_id: query = query.filter(Sorusturma.personel_id == personel_id)
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