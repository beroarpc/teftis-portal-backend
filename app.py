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

@app.route('/dashboard-data', methods=['GET'])
@jwt_required()
def dashboard_data():
    current_username = get_jwt_identity()
    user = User.query.filter_by(username=current_username).first()
    if not user: return jsonify(message="Token geçersiz, kullanıcı bulunamadı"), 404
    return jsonify(karsilama=f"Hoş geldiniz, sayın {user.rol.title()}", denetim_sayisi=15, aktif_soruşturma=5, rol=user.rol), 200

@app.route('/api/users', methods=['GET'])
@roller_gerekiyor('başkan')
def get_users():
    users = User.query.all()
    return jsonify([{'id': user.id, 'username': user.username, 'rol': user.rol} for user in users])

@app.route('/api/users', methods=['POST'])
@roller_gerekiyor('başkan')
def create_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    rol = data.get('rol')
    if not all([username, password, rol]):
        return jsonify(message="Kullanıcı adı, şifre ve rol zorunludur."), 400
    if User.query.filter_by(username=username).first():
        return jsonify(message="Bu kullanıcı adı zaten mevcut."), 409
    
    new_user = User(username=username, rol=rol)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify(message=f"'{username}' kullanıcısı başarıyla oluşturuldu."), 201

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@roller_gerekiyor('başkan')
def delete_user(user_id):
    user_to_delete = User.query.get(user_id)
    if not user_to_delete:
        return jsonify(message="Kullanıcı bulunamadı."), 404
    if user_to_delete.rol == 'başkan':
        return jsonify(message="Başkan rolündeki kullanıcı silinemez."), 403
    Sorusturma.query.filter_by(atanan_mufettis_id=user_id).update({"atanan_mufettis_id": None})
    db.session.delete(user_to_delete)
    db.session.commit()
    return jsonify(message=f"'{user_to_delete.username}' kullanıcısı başarıyla silindi."), 200

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
    if not sorusturma: return jsonify(message="Soruşturma bulunamadı"), 404
    dosyalar_listesi = [{'id': dosya.id, 'dosya_adi': dosya.dosya_adi, 'dosya_url': dosya.dosya_url} for dosya in sorusturma.dosyalar]
    atanan_mufettis_adi = sorusturma.atanan_mufettis.username if sorusturma.atanan_mufettis else None
    personel_adi = f"{sorusturma.hakkindaki_personel.ad} {sorusturma.hakkindaki_personel.soyad}" if sorusturma.hakkindaki_personel else "Belirtilmemiş"
    cezalar_listesi = [{'id': ceza.id, 'ceza_turu': ceza.ceza_turu, 'aciklama': ceza.aciklama, 'verilme_tarihi': ceza.verilme_tarihi.strftime('%Y-%m-%d')} for ceza in sorusturma.cezalar]
    sonuc = {'id': sorusturma.id, 'sorusturma_no': sorusturma.sorusturma_no, 'konu': sorusturma.konu, 'olusturma_tarihi': sorusturma.olusturma_tarihi.strftime('%Y-%m-%d %H:%M:%S'), 'durum': sorusturma.durum, 'onay_durumu': sorusturma.onay_durumu, 'dosyalar': dosyalar_listesi, 'atanan_mufettis': atanan_mufettis_adi, 'hakkindaki_personel': personel_adi, 'cezalar': cezalar_listesi}
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
        return jsonify([{'id': mufettis.id, 'username': mufettis.username} for mufettis in mufettisler])
    except Exception as e:
        return jsonify(message=f"Sunucuda bir hata oluştu: {str(e)}"), 500

@app.route('/api/sorusturmalar/<int:sorusturma_id>/ata', methods=['POST'])
@roller_gerekiyor('başkan')
def ata_mufettis(sorusturma_id):
    data = request.get_json()
    mufettis_id = data.get('mufettis_id')
    if not mufettis_id: return jsonify(message="Müfettiş ID'si zorunludur."), 400
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
    if 'sicil_no' not in request.form or 'ad' not in request.form or 'soyad' not in request.form:
        return jsonify(message="Sicil No, Ad ve Soyad alanları zorunludur"), 400
    yeni_personel = Personel(sicil_no=request.form['sicil_no'], ad=request.form['ad'], soyad=request.form['soyad'], unvan=request.form.get('unvan'), sube=request.form.get('sube'))
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

@app.route('/api/personel', methods=['GET'])
@jwt_required()
def get_personel_listesi():
    personeller = Personel.query.all()
    return jsonify([{'id': p.id, 'sicil_no': p.sicil_no, 'ad': p.ad, 'soyad': p.soyad, 'unvan': p.unvan, 'aktif_mi': p.aktif_mi} for p in personeller])

@app.route('/api/personel/<int:personel_id>', methods=['GET'])
@jwt_required()
def get_personel_detay(personel_id):
    personel = Personel.query.get(personel_id)
    if not personel:
        return jsonify(message="Personel bulunamadı"), 404
    sorusturmalar_listesi = [{'id': s.id, 'sorusturma_no': s.sorusturma_no, 'konu': s.konu} for s in personel.sorusturmalar]
    cezalar_listesi = [{'id': c.id, 'ceza_turu': c.ceza_turu, 'verilme_tarihi': c.verilme_tarihi.strftime('%Y-%m-%d')} for c in personel.cezalar]
    sonuc = {'id': personel.id, 'sicil_no': personel.sicil_no, 'ad': personel.ad, 'soyad': personel.soyad, 'unvan': personel.unvan, 'sube': personel.sube, 'ise_baslama_tarihi': personel.ise_baslama_tarihi.strftime('%Y-%m-%d') if personel.ise_baslama_tarihi else None, 'aktif_mi': personel.aktif_mi, 'profil_resmi_url': personel.profil_resmi_url, 'sorusturmalar': sorusturmalar_listesi, 'cezalar': cezalar_listesi}
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
    personel.sube = data.get('sube', personel.sube)
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

@app.route('/api/sorusturmalar/<int:sorusturma_id>/ceza-ekle', methods=['POST'])
@roller_gerekiyor('başkan')
def add_ceza_to_sorusturma(sorusturma_id):
    sorusturma = Sorusturma.query.get(sorusturma_id)
    if not sorusturma:
        return jsonify(message="Soruşturma bulunamadı."), 404
    if not sorusturma.hakkindaki_personel:
        return jsonify(message="Bu soruşturma bir personele bağlı değil, ceza eklenemez."), 400
    data = request.get_json()
    ceza_turu = data.get('ceza_turu')
    verilme_tarihi_str = data.get('verilme_tarihi')
    aciklama = data.get('aciklama')
    if not all([ceza_turu, verilme_tarihi_str]):
        return jsonify(message="Ceza türü ve verilme tarihi zorunludur."), 400
    try:
        verilme_tarihi = datetime.strptime(verilme_tarihi_str, '%Y-%m-%d').date()
    except ValueError:
        return jsonify(message="Tarih formatı geçersiz. Lütfen YYYY-MM-DD formatında girin."), 400
    yeni_ceza = Ceza(ceza_turu=ceza_turu, aciklama=aciklama, verilme_tarihi=verilme_tarihi, sorusturma_id=sorusturma.id, personel_id=sorusturma.personel_id)
    db.session.add(yeni_ceza)
    db.session.commit()
    return jsonify(message="Ceza başarıyla eklendi."), 201

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