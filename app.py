from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, send_from_directory, jsonify
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import pandas as pd
import io
from datetime import datetime
import cv2
import json
import bleach
from PIL import Image
import base64
from sqlalchemy import text, inspect

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///school.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

def get_system_setting(key, default_value="0"):
    """الحصول على إعداد النظام مع القيمة الافتراضية"""
    try:
        setting = SystemSettings.query.filter_by(setting_key=key).first()
        return setting.setting_value if setting else default_value
    except:
        return default_value

def set_system_setting(key, value, description=None):
    """تعيين إعداد النظام"""
    try:
        setting = SystemSettings.query.filter_by(setting_key=key).first()
        if setting:
            setting.setting_value = value
            if description:
                setting.description = description
        else:
            setting = SystemSettings(setting_key=key, setting_value=value, description=description)
            db.session.add(setting)
        db.session.commit()
        return True
    except:
        db.session.rollback()
        return False

def get_school_settings():
    """الحصول على إعدادات المدرسة"""
    try:
        settings = SchoolSettings.query.first()
        if not settings:
            # إنشاء إعدادات افتراضية إذا لم تكن موجودة
            settings = SchoolSettings(
                school_name="اسم المدرسة",
                school_address="عنوان المدرسة",
                school_phone="",
                school_email="",
                school_vision="رؤية المدرسة",
                school_mission="رسالة المدرسة",
                school_values="",
                google_maps_url="",
                youtube_url="",
                instagram_url="",
                telegram_url="",
                snapchat_url="",
                whatsapp_url="",
                academic_year="2024-2025",
                academic_semester="الفصل الدراسي الأول"
            )
            db.session.add(settings)
            db.session.commit()
        return settings
    except Exception as e:
        print(f"خطأ في get_school_settings: {e}")
        # إرجاع إعدادات افتراضية في حالة الخطأ
        return SchoolSettings(
            school_name="اسم المدرسة",
            school_address="عنوان المدرسة",
            school_phone="",
            school_email="",
            school_vision="رؤية المدرسة",
            school_mission="رسالة المدرسة",
            school_values="",
            google_maps_url="",
            youtube_url="",
            instagram_url="",
            telegram_url="",
            snapchat_url="",
            whatsapp_url="",
            academic_year="2024-2025",
            academic_semester="الفصل الدراسي الأول"
        )

def log_activity(operation_type, table_name, record_id=None, old_data=None, new_data=None, description=None):
    """
    تسجيل نشاط في جدول سجل العمليات
    
    Args:
        operation_type (str): نوع العملية (إضافة، تعديل، حذف)
        table_name (str): اسم الجدول
        record_id (str): معرف السجل
        old_data (dict): البيانات القديمة (للعمليات من نوع تعديل)
        new_data (dict): البيانات الجديدة
        description (str): وصف العملية
    """
    try:
        # الحصول على بيانات المستخدم من الجلسة
        user_civil_id = session.get('civil_id')
        user_name = session.get('name')
        user_subject = session.get('subject')
        user_job_title = session.get('job_title')
        
        # الحصول على معلومات الطلب
        ip_address = request.remote_addr if request else None
        user_agent = request.headers.get('User-Agent') if request else None
        
        # تحويل البيانات إلى JSON
        old_data_json = json.dumps(old_data, ensure_ascii=False) if old_data else None
        new_data_json = json.dumps(new_data, ensure_ascii=False) if new_data else None
        
        # إنشاء سجل النشاط
        activity_log = ActivityLog(
            operation_type=operation_type,
            table_name=table_name,
            record_id=str(record_id) if record_id else None,
            user_civil_id=user_civil_id,
            user_name=user_name,
            user_subject=user_subject,
            user_job_title=user_job_title,
            old_data=old_data_json,
            new_data=new_data_json,
            description=description,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        db.session.add(activity_log)
        db.session.commit()
        
    except Exception as e:
        # في حالة حدوث خطأ، لا نريد أن يؤثر على العملية الرئيسية
        print(f"Error logging activity: {e}")
        db.session.rollback()

def get_user_data_from_session():
    """الحصول على بيانات المستخدم من الجلسة"""
    return {
        'civil_id': session.get('civil_id'),
        'name': session.get('name'),
        'subject': session.get('subject'),
        'job_title': session.get('job_title'),
        'role': session.get('role')
    }

def clean_html_content(html_content):
    """تنظيف محتوى HTML لمنع XSS"""
    allowed_tags = [
        'p', 'br', 'strong', 'b', 'em', 'i', 'u', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
        'ul', 'ol', 'li', 'blockquote', 'pre', 'code', 'a', 'img', 'div', 'span',
        'table', 'thead', 'tbody', 'tr', 'td', 'th', 'hr'
    ]
    allowed_attributes = {
        'a': ['href', 'title', 'target'],
        'img': ['src', 'alt', 'title', 'width', 'height', 'style'],
        'div': ['class', 'style'],
        'span': ['class', 'style'],
        'p': ['class', 'style'],
        'table': ['class', 'style'],
        'tr': ['class', 'style'],
        'td': ['class', 'style'],
        'th': ['class', 'style']
    }
    return bleach.clean(html_content, tags=allowed_tags, attributes=allowed_attributes, strip=True)

def compress_image(image_path, max_size=(800, 600), quality=85):
    """ضغط الصورة مع الحفاظ على النسبة"""
    try:
        with Image.open(image_path) as img:
            # تحويل إلى RGB إذا كانت الصورة في وضع آخر
            if img.mode in ('RGBA', 'LA', 'P'):
                img = img.convert('RGB')
            
            # تغيير الحجم مع الحفاظ على النسبة
            img.thumbnail(max_size, Image.Resampling.LANCZOS)
            
            # حفظ الصورة المضغوطة
            img.save(image_path, 'JPEG', quality=quality, optimize=True)
            return True
    except Exception as e:
        print(f"خطأ في ضغط الصورة: {e}")
        return False

def save_uploaded_image(file, folder='news'):
    """حفظ الصورة المرفوعة مع الضغط"""
    try:
        if file and file.filename:
            # إنشاء مجلد الصور إذا لم يكن موجوداً
            images_dir = os.path.join('assets', 'images', folder)
            os.makedirs(images_dir, exist_ok=True)
            
            # إنشاء اسم فريد للملف
            filename = datetime.now().strftime('%Y%m%d%H%M%S_') + secure_filename(file.filename)
            file_path = os.path.join(images_dir, filename)
            
            # حفظ الملف
            file.save(file_path)
            
            # ضغط الصورة
            compress_image(file_path)
            
            return filename
    except Exception as e:
        print(f"خطأ في حفظ الصورة: {e}")
        return None

class User(db.Model):
    civil_id = db.Column(db.String(20), primary_key=True)  # الرقم المدني
    name = db.Column(db.String(100), nullable=False)      # الاسم
    subject = db.Column(db.String(100), nullable=True)    # المادة
    password = db.Column(db.String(200), nullable=False)  # كلمة المرور (مشفر)
    role = db.Column(db.String(20), nullable=False)       # الصلاحية (مشرف/عادي)
    job_title = db.Column(db.String(50), nullable=True)   # المسمى الوظيفي الجديد

class Seat(db.Model):
    civil_id = db.Column(db.String(20), primary_key=True)  # الرقم المدني
    name = db.Column(db.String(100), nullable=False)      # الاسم
    seat_number = db.Column(db.String(20), nullable=False) # رقم الجلوس
    main_committee = db.Column(db.String(20), nullable=False) # اللجنة الرئيسية
    sub_committee = db.Column(db.String(20), nullable=False)  # اللجنة الفرعية
    location = db.Column(db.String(100), nullable=True)   # موقع اللجنة

class News(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    details = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(200), nullable=True)
    date = db.Column(db.String(20), nullable=False)

class Observer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    civil_id = db.Column(db.String(20), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    assignment = db.Column(db.String(50), nullable=False)
    main_committee = db.Column(db.String(20), nullable=False)
    sub_committee = db.Column(db.String(20), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    day = db.Column(db.String(20), nullable=False)
    date = db.Column(db.String(20), nullable=False)

class Student(db.Model):
    civil_id = db.Column(db.String(20), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    grade = db.Column(db.String(20), nullable=False)
    section = db.Column(db.String(10), nullable=False)
    password = db.Column(db.String(100), nullable=False)

class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    stage = db.Column(db.String(20), nullable=False)
    subject = db.Column(db.String(100), nullable=False)

class EducationalMaterial(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    stage = db.Column(db.String(20), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    material_type = db.Column(db.String(20), nullable=False)  # PDF أو فيديو
    file_path = db.Column(db.String(500), nullable=True)      # مسار الملف (للـ PDF)
    video_url = db.Column(db.String(500), nullable=True)      # رابط الفيديو
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)

class SchoolActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)          # اسم النشاط
    description = db.Column(db.Text, nullable=False)          # وصف مختصر
    activity_date = db.Column(db.Date, nullable=False)        # تاريخ النشاط
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    # إزالة الحقول القديمة للوسائط الفردية
    # media_type = db.Column(db.String(20), nullable=False)     # صورة أو فيديو
    # file_path = db.Column(db.String(500), nullable=False)     # مسار الملف
    # file_name = db.Column(db.String(200), nullable=False)     # اسم الملف الأصلي
    # thumbnail_path = db.Column(db.String(500), nullable=True) # مسار الصورة المصغرة للفيديو
    
    # العلاقة مع الوسائط المتعددة
    media = db.relationship('ActivityMedia', backref='activity', lazy=True, cascade='all, delete-orphan')

class ActivityMedia(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    activity_id = db.Column(db.Integer, db.ForeignKey('school_activity.id'), nullable=False)
    media_type = db.Column(db.String(20), nullable=False)     # صورة أو فيديو
    file_path = db.Column(db.String(500), nullable=False)     # مسار الملف
    file_name = db.Column(db.String(200), nullable=False)     # اسم الملف الأصلي
    thumbnail_path = db.Column(db.String(500), nullable=True) # مسار الصورة المصغرة للفيديو
    is_primary = db.Column(db.Boolean, default=False)         # هل هي الصورة الرئيسية
    display_order = db.Column(db.Integer, default=0)          # ترتيب العرض
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)

class CalendarEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)         # عنوان الحدث
    event_type = db.Column(db.String(20), nullable=False)     # نوع الحدث (exam, activity, holiday, meeting)
    start_date = db.Column(db.Date, nullable=False)           # تاريخ البداية
    end_date = db.Column(db.Date, nullable=False)             # تاريخ النهاية
    event_time = db.Column(db.String(10), nullable=True)      # وقت الحدث
    location = db.Column(db.String(200), nullable=True)       # موقع الحدث
    description = db.Column(db.Text, nullable=True)           # وصف الحدث
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Inquiry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_civil_id = db.Column(db.String(20), db.ForeignKey('student.civil_id'), nullable=False)
    student_name = db.Column(db.String(100), nullable=False)
    student_grade = db.Column(db.String(20), nullable=False)
    student_section = db.Column(db.String(10), nullable=False)  # شعبة الطالب
    user_type = db.Column(db.String(20), nullable=False)
    message_type = db.Column(db.String(20), nullable=False)  # استفسار، شكوى، مقترح
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='قيد المراجعة')
    response = db.Column(db.Text, nullable=True)
    is_read = db.Column(db.Boolean, default=False)  # هل تم قراءة الرد
    submission_date = db.Column(db.DateTime, default=datetime.utcnow)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class SystemSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    setting_key = db.Column(db.String(100), unique=True, nullable=False)
    setting_value = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text, nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class SchoolSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    school_logo = db.Column(db.String(255), nullable=True)
    school_name = db.Column(db.String(200), nullable=False)
    school_address = db.Column(db.Text, nullable=True)
    school_phone = db.Column(db.String(50), nullable=True)
    school_email = db.Column(db.String(100), nullable=True)
    school_vision = db.Column(db.Text, nullable=True)
    school_mission = db.Column(db.Text, nullable=True)
    school_values = db.Column(db.Text, nullable=True)
    google_maps_url = db.Column(db.String(500), nullable=True)
    youtube_url = db.Column(db.String(500), nullable=True)
    instagram_url = db.Column(db.String(500), nullable=True)
    telegram_url = db.Column(db.String(500), nullable=True)
    snapchat_url = db.Column(db.String(500), nullable=True)
    whatsapp_url = db.Column(db.String(500), nullable=True)
    academic_year = db.Column(db.String(50), nullable=True)
    academic_semester = db.Column(db.String(50), nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    operation_type = db.Column(db.String(20), nullable=False)  # إضافة، تعديل، حذف
    table_name = db.Column(db.String(50), nullable=False)      # اسم الجدول (users, seats, observers, etc.)
    record_id = db.Column(db.String(50), nullable=True)        # معرف السجل (civil_id أو id)
    
    # بيانات المستخدم الذي قام بالعملية
    user_civil_id = db.Column(db.String(20), nullable=True)    # الرقم المدني للمستخدم
    user_name = db.Column(db.String(100), nullable=True)       # اسم المستخدم
    user_subject = db.Column(db.String(100), nullable=True)    # مادة المستخدم
    user_job_title = db.Column(db.String(50), nullable=True)   # المسمى الوظيفي
    
    # البيانات قبل التعديل (للعمليات من نوع تعديل)
    old_data = db.Column(db.Text, nullable=True)              # البيانات القديمة (JSON)
    
    # البيانات بعد التعديل أو البيانات الجديدة
    new_data = db.Column(db.Text, nullable=True)              # البيانات الجديدة (JSON)
    
    # تفاصيل إضافية
    description = db.Column(db.Text, nullable=True)           # وصف العملية
    ip_address = db.Column(db.String(45), nullable=True)      # عنوان IP
    user_agent = db.Column(db.Text, nullable=True)           # User Agent
    
    # التواريخ
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@app.route('/')
def home():
    news_list = News.query.order_by(News.id.desc()).limit(6).all()
    school_settings = get_school_settings()
    current_year = datetime.now().year
    return render_template('index.html', news_list=news_list, school_settings=school_settings, current_year=current_year)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        civil_id = request.form['civil_id']
        password = request.form['password']
        user = User.query.filter_by(civil_id=civil_id).first()
        if user and check_password_hash(user.password, password):
            session['civil_id'] = user.civil_id
            session['name'] = user.name
            session['role'] = user.role
            flash('تم تسجيل الدخول بنجاح!', 'success')
            if user.role == 'مشرف' or user.role == 'مشرف محتوى':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash('الرقم المدني أو كلمة المرور غير صحيحة', 'danger')
    school_settings = get_school_settings()
    current_year = datetime.now().year
    return render_template('login.html', school_settings=school_settings, current_year=current_year)

@app.route('/admin')
def admin_dashboard():
    if 'role' in session and (session['role'] == 'مشرف' or session['role'] == 'مشرف محتوى'):
        # جلب عدد الاستفسارات المعلقة (قيد المراجعة)
        try:
            pending_inquiries_count = Inquiry.query.filter_by(status='قيد المراجعة').count()
        except Exception as e:
            # إذا كان هناك خطأ في قاعدة البيانات، عرض رسالة للمشرف
            pending_inquiries_count = 0
            flash('يوجد مشكلة في قاعدة البيانات. يرجى الضغط على زر "إصلاح قاعدة البيانات" لحل المشكلة.', 'warning')
        school_settings = get_school_settings()
        current_year = datetime.now().year
        return render_template('admin.html', pending_inquiries_count=pending_inquiries_count, school_settings=school_settings, current_year=current_year)
    return redirect(url_for('login'))

@app.route('/user')
def user_dashboard():
    if 'role' in session and session['role'] == 'عادي':
        try:
            # حساب الاستفسارات غير المقروءة للمستخدم
            unread_inquiries_count = Inquiry.query.filter_by(
                student_civil_id=session['civil_id'],
                status='تم الرد',
                is_read=False
            ).count()
            
            # التحقق من تفعيل استفسارات المعلمين
            teacher_inquiries_enabled = get_system_setting('teacher_inquiries_enabled', '1')
            
            school_settings = get_school_settings()
            current_year = datetime.now().year
            return render_template('user_home.html', 
                                 unread_inquiries_count=unread_inquiries_count,
                                 teacher_inquiries_enabled=teacher_inquiries_enabled,
                                 school_settings=school_settings,
                                 current_year=current_year)
        except Exception as e:
            school_settings = get_school_settings()
            current_year = datetime.now().year
            return render_template('user_home.html', 
                                 unread_inquiries_count=0,
                                 teacher_inquiries_enabled='1',
                                 school_settings=school_settings,
                                 current_year=current_year)
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/admin/users', methods=['GET', 'POST'])
def admin_users():
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    if request.method == 'POST':
        civil_id = request.form.get('civil_id')
        name = request.form.get('name')
        subject = request.form.get('subject')
        subject_other = request.form.get('subject_other')
        if subject_other and subject_other.strip():
            subject = subject_other.strip()
        password = request.form.get('password')
        role = request.form.get('role')
        job_title = request.form.get('job_title')
        if len(civil_id) != 12 or not civil_id.isdigit():
            flash('الرقم المدني يجب أن يكون 12 رقمًا', 'danger')
        elif User.query.filter_by(civil_id=civil_id).first():
            flash('المستخدم بهذا الرقم المدني موجود بالفعل', 'danger')
        elif not subject or not subject.strip():
            flash('يجب اختيار أو إدخال المادة', 'danger')
        elif not job_title or not job_title.strip():
            flash('يجب اختيار المسمى الوظيفي', 'danger')
        else:
            hashed_password = generate_password_hash(password)
            user = User(civil_id=civil_id, name=name, subject=subject, password=hashed_password, role=role, job_title=job_title)
            db.session.add(user)
            db.session.commit()
            
            # تسجيل العملية في سجل العمليات
            log_activity(
                operation_type='إضافة',
                table_name='users',
                record_id=civil_id,
                new_data={
                    'civil_id': civil_id,
                    'name': name,
                    'subject': subject,
                    'role': role,
                    'job_title': job_title
                },
                description=f'تم إضافة مستخدم جديد: {name}'
            )
            
            flash('تم إضافة المستخدم بنجاح', 'success')
        return redirect(url_for('admin_users'))
    users = User.query.all()
    subjects = sorted(set(u.subject for u in users if u.subject and u.subject.strip() != '-'))
    school_settings = get_school_settings()
    current_year = datetime.now().year
    return render_template('admin_users.html', users=users, subjects=subjects, school_settings=school_settings, current_year=current_year)

@app.route('/admin/users/edit/<civil_id>', methods=['GET', 'POST'])
def edit_user(civil_id):
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    user = User.query.filter_by(civil_id=civil_id).first_or_404()
    users = User.query.all()
    subjects = sorted(set(u.subject for u in users if u.subject and u.subject.strip() != '-'))
    if request.method == 'POST':
        name = request.form.get('name')
        subject = request.form.get('subject')
        subject_other = request.form.get('subject_other')
        if subject_other and subject_other.strip():
            subject = subject_other.strip()
        password = request.form.get('password')
        role = request.form.get('role')
        job_title = request.form.get('job_title')
        # حفظ البيانات القديمة قبل التعديل
        old_data = {
            'civil_id': user.civil_id,
            'name': user.name,
            'subject': user.subject,
            'role': user.role,
            'job_title': user.job_title
        }
        
        user.name = name
        user.subject = subject
        if password:
            user.password = generate_password_hash(password)
        user.role = role
        user.job_title = job_title
        db.session.commit()
        
        # تسجيل العملية في سجل العمليات
        log_activity(
            operation_type='تعديل',
            table_name='users',
            record_id=civil_id,
            old_data=old_data,
            new_data={
                'civil_id': user.civil_id,
                'name': user.name,
                'subject': user.subject,
                'role': user.role,
                'job_title': user.job_title
            },
            description=f'تم تعديل بيانات المستخدم: {name}'
        )
        
        flash('تم تعديل بيانات المستخدم بنجاح', 'success')
        return redirect(url_for('admin_users'))
    school_settings = get_school_settings()
    current_year = datetime.now().year
    return render_template('edit_user.html', user=user, subjects=subjects, school_settings=school_settings, current_year=current_year)

@app.route('/admin/users/delete/<civil_id>', methods=['POST'])
def delete_user(civil_id):
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    user = User.query.filter_by(civil_id=civil_id).first_or_404()
    
    # حفظ بيانات المستخدم قبل الحذف
    user_data = {
        'civil_id': user.civil_id,
        'name': user.name,
        'subject': user.subject,
        'role': user.role,
        'job_title': user.job_title
    }
    
    db.session.delete(user)
    db.session.commit()
    
    # تسجيل العملية في سجل العمليات
    log_activity(
        operation_type='حذف',
        table_name='users',
        record_id=civil_id,
        old_data=user_data,
        description=f'تم حذف المستخدم: {user_data["name"]}'
    )
    
    flash('تم حذف المستخدم', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/delete_all', methods=['POST'])
def delete_all_users():
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    deleted = User.query.filter(User.role != 'مشرف', User.role != 'مشرف محتوى').delete()
    db.session.commit()
    
    # تسجيل العملية في سجل العمليات
    log_activity(
        operation_type='حذف',
        table_name='users',
        description=f'تم حذف {deleted} مستخدم عادي'
    )
    
    flash(f'تم حذف {deleted} مستخدم عادي بنجاح. لم يتم حذف أي مشرف أو مشرف محتوى.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/upload', methods=['POST'])
def upload_users():
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    file = request.files.get('excel_file')
    if not file:
        flash('يرجى اختيار ملف إكسل', 'danger')
        return redirect(url_for('admin_users'))
    try:
        df = pd.read_excel(file, engine='openpyxl')
        required_cols = ['الرقم المدني', 'الاسم', 'المادة', 'كلمة المرور', 'الصلاحية', 'المسمى الوظيفي']
        if not all(col in df.columns for col in required_cols):
            flash('ملف الإكسل يجب أن يحتوي على الأعمدة: ' + ', '.join(required_cols), 'danger')
            return redirect(url_for('admin_users'))
        added = 0
        for _, row in df.iterrows():
            civil_id = str(row['الرقم المدني']) if pd.notna(row['الرقم المدني']) and str(row['الرقم المدني']).strip() else '-'
            name = str(row['الاسم']) if pd.notna(row['الاسم']) and str(row['الاسم']).strip() else '-'
            subject = str(row['المادة']) if pd.notna(row['المادة']) and str(row['المادة']).strip() else '-'
            password = str(row['كلمة المرور']) if pd.notna(row['كلمة المرور']) and str(row['كلمة المرور']).strip() else '-'
            role = str(row['الصلاحية']) if pd.notna(row['الصلاحية']) and str(row['الصلاحية']).strip() else '-'
            job_title = str(row['المسمى الوظيفي']) if pd.notna(row['المسمى الوظيفي']) and str(row['المسمى الوظيفي']).strip() else '-'
            if len(civil_id) == 12 and civil_id.isdigit() and not User.query.filter_by(civil_id=civil_id).first():
                hashed_password = generate_password_hash(password)
                user = User(civil_id=civil_id, name=name, subject=subject, password=hashed_password, role=role, job_title=job_title)
                db.session.add(user)
                added += 1
        db.session.commit()
        
        # تسجيل العملية في سجل العمليات
        log_activity(
            operation_type='إضافة',
            table_name='users',
            description=f'تم رفع ملف إكسل وإضافة {added} مستخدم جديد'
        )
        
        flash(f'تمت إضافة {added} مستخدم جديد', 'success')
    except Exception as e:
        flash('حدث خطأ أثناء معالجة الملف: ' + str(e), 'danger')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/template')
def download_users_template():
    output = io.BytesIO()
    df = pd.DataFrame(columns=['الرقم المدني', 'الاسم', 'المادة', 'كلمة المرور', 'الصلاحية', 'المسمى الوظيفي'])
    df.to_excel(output, index=False, engine='openpyxl')
    output.seek(0)
    return send_file(output, as_attachment=True, download_name='users_template.xlsx', mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

@app.route('/admin/seats', methods=['GET', 'POST'])
def admin_seats():
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    if request.method == 'POST':
        civil_id = request.form.get('civil_id')
        name = request.form.get('name')
        seat_number = request.form.get('seat_number')
        main_committee = request.form.get('main_committee')
        sub_committee = request.form.get('sub_committee')
        location = request.form.get('location')
        if len(civil_id) != 12 or not civil_id.isdigit():
            flash('الرقم المدني يجب أن يكون 12 رقمًا', 'danger')
        elif Seat.query.filter_by(civil_id=civil_id).first():
            flash('يوجد رقم جلوس مسجل لهذا الرقم المدني بالفعل', 'danger')
        else:
            seat = Seat(civil_id=civil_id, name=name, seat_number=seat_number, main_committee=main_committee, sub_committee=sub_committee, location=location)
            db.session.add(seat)
            db.session.commit()
            
            # تسجيل العملية في سجل العمليات
            log_activity(
                operation_type='إضافة',
                table_name='seats',
                record_id=civil_id,
                new_data={
                    'civil_id': civil_id,
                    'name': name,
                    'seat_number': seat_number,
                    'main_committee': main_committee,
                    'sub_committee': sub_committee,
                    'location': location
                },
                description=f'تم إضافة رقم جلوس للطالب: {name}'
            )
            
            flash('تم تسجيل رقم الجلوس بنجاح', 'success')
        return redirect(url_for('admin_seats'))
    seats = Seat.query.all()
    main_committees = ['الأولى','الثانية','الثالثة','الرابعة','الخامسة','السادسة']
    sub_committees = [str(i) for i in range(1, 11)]
    school_settings = get_school_settings()
    current_year = datetime.now().year
    return render_template('admin_seats.html', seats=seats, main_committees=main_committees, sub_committees=sub_committees, school_settings=school_settings, current_year=current_year)

@app.route('/admin/seats/upload', methods=['POST'])
def upload_seats():
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    file = request.files.get('excel_file')
    if not file:
        flash('يرجى اختيار ملف إكسل', 'danger')
        return redirect(url_for('admin_seats'))
    try:
        df = pd.read_excel(file, engine='openpyxl')
        required_cols = ['الرقم المدني', 'الاسم', 'رقم الجلوس', 'اللجنة الرئيسية', 'اللجنة الفرعية', 'موقع اللجنة']
        if not all(col in df.columns for col in required_cols):
            flash('ملف الإكسل يجب أن يحتوي على الأعمدة: الرقم المدني، الاسم، رقم الجلوس، اللجنة الرئيسية، اللجنة الفرعية، موقع اللجنة', 'danger')
            return redirect(url_for('admin_seats'))
        added = 0
        for _, row in df.iterrows():
            civil_id = str(row['الرقم المدني'])
            name = str(row['الاسم'])
            seat_number = str(row['رقم الجلوس'])
            main_committee = str(row['اللجنة الرئيسية'])
            sub_committee = str(row['اللجنة الفرعية'])
            location = str(row['موقع اللجنة'])
            if len(civil_id) == 12 and civil_id.isdigit() and not Seat.query.filter_by(civil_id=civil_id).first():
                seat = Seat(civil_id=civil_id, name=name, seat_number=seat_number, main_committee=main_committee, sub_committee=sub_committee, location=location)
                db.session.add(seat)
                added += 1
        db.session.commit()
        
        # تسجيل العملية في سجل العمليات
        log_activity(
            operation_type='إضافة',
            table_name='seats',
            description=f'تم رفع ملف إكسل وإضافة {added} رقم جلوس جديد'
        )
        
        flash(f'تمت إضافة {added} رقم جلوس جديد', 'success')
    except Exception as e:
        flash('حدث خطأ أثناء معالجة الملف: ' + str(e), 'danger')
    return redirect(url_for('admin_seats'))

@app.route('/admin/seats/template')
def download_seats_template():
    output = io.BytesIO()
    df = pd.DataFrame(columns=['الرقم المدني', 'الاسم', 'رقم الجلوس', 'اللجنة الرئيسية', 'اللجنة الفرعية', 'موقع اللجنة'])
    df.to_excel(output, index=False, engine='openpyxl')
    output.seek(0)
    return send_file(output, as_attachment=True, download_name='seats_template.xlsx', mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

@app.route('/admin/seats/export')
def export_seats():
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    seats = Seat.query.all()
    df = pd.DataFrame([
        {
            'الرقم المدني': s.civil_id,
            'الاسم': s.name,
            'رقم الجلوس': s.seat_number,
            'اللجنة الرئيسية': s.main_committee,
            'اللجنة الفرعية': s.sub_committee,
            'موقع اللجنة': s.location
        } for s in seats
    ])
    output = io.BytesIO()
    df.to_excel(output, index=False, engine='openpyxl')
    output.seek(0)
    return send_file(output, as_attachment=True, download_name='seats_export.xlsx', mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

@app.route('/admin/seats/print_committees')
def print_committees():
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    
    # الحصول على الفلاتر من URL
    name_filter = request.args.get('name_filter', '').strip()
    main_filter = request.args.get('main_filter', '').strip()
    sub_filter = request.args.get('sub_filter', '').strip()
    
    # بناء الاستعلام
    query = Seat.query
    
    # تطبيق الفلاتر
    if name_filter:
        query = query.filter(Seat.name.contains(name_filter))
    if main_filter:
        query = query.filter(Seat.main_committee == main_filter)
    if sub_filter:
        query = query.filter(Seat.sub_committee == sub_filter)
    
    # الحصول على البيانات مرتبة حسب اللجنة الرئيسية ثم الفرعية ثم رقم الجلوس
    seats = query.order_by(Seat.main_committee, Seat.sub_committee, Seat.seat_number).all()
    
    # تنظيم البيانات حسب اللجان
    committees_data = {}
    for seat in seats:
        main_key = seat.main_committee
        sub_key = seat.sub_committee
        
        if main_key not in committees_data:
            committees_data[main_key] = {}
        if sub_key not in committees_data[main_key]:
            committees_data[main_key][sub_key] = []
        
        committees_data[main_key][sub_key].append(seat)
    
    # الحصول على إعدادات المدرسة
    school_settings = get_school_settings()
    
    return render_template('print_committees.html', 
                         committees_data=committees_data,
                         school_settings=school_settings)

@app.route('/admin/seats/delete_all', methods=['POST'])
def delete_all_seats():
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    deleted = Seat.query.delete()
    db.session.commit()
    
    # تسجيل العملية في سجل العمليات
    log_activity(
        operation_type='حذف',
        table_name='seats',
        description=f'تم حذف جميع بيانات أرقام الجلوس ({deleted} سجل)'
    )
    
    flash(f'تم حذف جميع بيانات أرقام الجلوس ({deleted} سجل)', 'success')
    return redirect(url_for('admin_seats'))

@app.route('/admin/seats/delete/<civil_id>', methods=['POST'])
def delete_seat(civil_id):
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    seat = Seat.query.filter_by(civil_id=civil_id).first_or_404()
    
    # حفظ بيانات السجل قبل الحذف
    seat_data = {
        'civil_id': seat.civil_id,
        'name': seat.name,
        'seat_number': seat.seat_number,
        'main_committee': seat.main_committee,
        'sub_committee': seat.sub_committee,
        'location': seat.location
    }
    
    db.session.delete(seat)
    db.session.commit()
    
    # تسجيل العملية في سجل العمليات
    log_activity(
        operation_type='حذف',
        table_name='seats',
        record_id=civil_id,
        old_data=seat_data,
        description=f'تم حذف رقم جلوس للطالب: {seat_data["name"]}'
    )
    
    flash('تم حذف السجل بنجاح', 'success')
    return redirect(url_for('admin_seats'))

@app.route('/admin/seats/edit/<civil_id>', methods=['GET', 'POST'])
def edit_seat(civil_id):
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    seat = Seat.query.filter_by(civil_id=civil_id).first_or_404()
    main_committees = ['الأولى','الثانية','الثالثة','الرابعة','الخامسة','السادسة']
    sub_committees = [str(i) for i in range(1, 11)]
    if request.method == 'POST':
        # حفظ البيانات القديمة قبل التعديل
        old_data = {
            'civil_id': seat.civil_id,
            'name': seat.name,
            'seat_number': seat.seat_number,
            'main_committee': seat.main_committee,
            'sub_committee': seat.sub_committee,
            'location': seat.location
        }
        
        seat.name = request.form.get('name')
        seat.seat_number = request.form.get('seat_number')
        seat.main_committee = request.form.get('main_committee')
        seat.sub_committee = request.form.get('sub_committee')
        seat.location = request.form.get('location')
        db.session.commit()
        
        # تسجيل العملية في سجل العمليات
        log_activity(
            operation_type='تعديل',
            table_name='seats',
            record_id=civil_id,
            old_data=old_data,
            new_data={
                'civil_id': seat.civil_id,
                'name': seat.name,
                'seat_number': seat.seat_number,
                'main_committee': seat.main_committee,
                'sub_committee': seat.sub_committee,
                'location': seat.location
            },
            description=f'تم تعديل بيانات رقم الجلوس للطالب: {seat.name}'
        )
        
        flash('تم تعديل بيانات السجل بنجاح', 'success')
        return redirect(url_for('admin_seats'))
    school_settings = get_school_settings()
    current_year = datetime.now().year
    return render_template('edit_seat.html', seat=seat, main_committees=main_committees, sub_committees=sub_committees, school_settings=school_settings, current_year=current_year)

@app.route('/admin/news', methods=['GET', 'POST'])
def admin_news():
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form.get('title')
        details = request.form.get('details')
        
        # تنظيف محتوى HTML لمنع XSS
        if details:
            details = clean_html_content(details)
        
        date = datetime.now().strftime('%Y-%m-%d')
        image_file = request.files.get('image')
        image_filename = None
        
        if image_file and image_file.filename:
            image_filename = save_uploaded_image(image_file, 'news')
        
        news = News(title=title, details=details, image=image_filename, date=date)
        db.session.add(news)
        db.session.commit()
        
        # تسجيل العملية في سجل العمليات
        log_activity(
            operation_type='إضافة',
            table_name='news',
            record_id=str(news.id),
            new_data={
                'id': news.id,
                'title': title,
                'details': details,
                'image': image_filename,
                'date': date
            },
            description=f'تم إضافة خبر جديد: {title}'
        )
        
        flash('تم إضافة الخبر بنجاح', 'success')
        return redirect(url_for('admin_news'))
    news_list = News.query.order_by(News.id.desc()).all()
    current_date = datetime.now().strftime('%Y-%m-%d')
    school_settings = get_school_settings()
    current_year = datetime.now().year
    return render_template('admin_news.html', news_list=news_list, current_date=current_date, school_settings=school_settings, current_year=current_year)

@app.route('/admin/news/delete/<int:news_id>', methods=['POST'])
def delete_news(news_id):
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    news = News.query.get_or_404(news_id)
    
    # حفظ بيانات الخبر قبل الحذف
    news_data = {
        'id': news.id,
        'title': news.title,
        'details': news.details,
        'image': news.image,
        'date': news.date
    }
    
    db.session.delete(news)
    db.session.commit()
    
    # تسجيل العملية في سجل العمليات
    log_activity(
        operation_type='حذف',
        table_name='news',
        record_id=str(news_id),
        old_data=news_data,
        description=f'تم حذف الخبر: {news_data["title"]}'
    )
    
    flash('تم حذف الخبر بنجاح', 'success')
    return redirect(url_for('admin_news'))

@app.route('/admin/news/delete_all', methods=['POST'])
def delete_all_news():
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    
    try:
        # حذف جميع الأخبار من قاعدة البيانات
        deleted = News.query.delete()
        db.session.commit()
        
        # تسجيل العملية في سجل العمليات
        log_activity(
            operation_type='حذف',
            table_name='news',
            description=f'تم حذف جميع الأخبار ({deleted} خبر)'
        )
        
        flash('تم حذف جميع الأخبار بنجاح', 'success')
    except Exception as e:
        db.session.rollback()
        flash('حدث خطأ أثناء حذف الأخبار', 'danger')
    
    return redirect(url_for('admin_news'))

@app.route('/admin/news/edit/<int:news_id>', methods=['GET', 'POST'])
def edit_news(news_id):
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    news = News.query.get_or_404(news_id)
    if request.method == 'POST':
        # حفظ البيانات القديمة قبل التعديل
        old_data = {
            'id': news.id,
            'title': news.title,
            'details': news.details,
            'image': news.image,
            'date': news.date
        }
        
        news.title = request.form.get('title')
        details = request.form.get('details')
        
        # تنظيف محتوى HTML لمنع XSS
        if details:
            details = clean_html_content(details)
        
        news.details = details
        news.date = request.form.get('date')
        image_file = request.files.get('image')
        if image_file and image_file.filename:
            image_filename = save_uploaded_image(image_file, 'news')
            news.image = image_filename
        db.session.commit()
        
        # تسجيل العملية في سجل العمليات
        log_activity(
            operation_type='تعديل',
            table_name='news',
            record_id=str(news_id),
            old_data=old_data,
            new_data={
                'id': news.id,
                'title': news.title,
                'details': news.details,
                'image': news.image,
                'date': news.date
            },
            description=f'تم تعديل الخبر: {news.title}'
        )
        
        flash('تم تعديل الخبر بنجاح', 'success')
        return redirect(url_for('admin_news'))
    school_settings = get_school_settings()
    current_year = datetime.now().year
    return render_template('edit_news.html', news=news, school_settings=school_settings, current_year=current_year)

@app.route('/news_all')
def news_all():
    news_list = News.query.order_by(News.id.desc()).all()
    school_settings = get_school_settings()
    current_year = datetime.now().year
    return render_template('news_all.html', news_list=news_list, school_settings=school_settings, current_year=current_year)

@app.route('/news/<int:news_id>')
def news_detail(news_id):
    news = News.query.get_or_404(news_id)
    school_settings = get_school_settings()
    current_year = datetime.now().year
    return render_template('news_detail.html', news=news, school_settings=school_settings, current_year=current_year)

@app.route('/assets/images/news/<filename>')
def news_image(filename):
    return send_from_directory('assets/images/news', filename)

@app.route('/api/upload_editor_image', methods=['POST'])
def upload_editor_image():
    """رفع صورة من محرر النصوص الغني"""
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return jsonify({'error': 'غير مصرح'}), 403
    
    try:
        if 'image' not in request.files:
            return jsonify({'error': 'لم يتم اختيار ملف'}), 400
        
        file = request.files['image']
        if file.filename == '':
            return jsonify({'error': 'لم يتم اختيار ملف'}), 400
        
        # التحقق من نوع الملف
        allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
        if not file.filename.lower().endswith(tuple('.' + ext for ext in allowed_extensions)):
            return jsonify({'error': 'نوع الملف غير مسموح'}), 400
        
        # التحقق من حجم الملف (5MB كحد أقصى)
        if len(file.read()) > 5 * 1024 * 1024:
            file.seek(0)  # إعادة تعيين المؤشر
            return jsonify({'error': 'حجم الملف كبير جداً (الحد الأقصى 5MB)'}), 400
        
        file.seek(0)  # إعادة تعيين المؤشر
        
        # حفظ الصورة
        filename = save_uploaded_image(file, 'news')
        if filename:
            image_url = url_for('news_image', filename=filename)
            return jsonify({
                'success': True,
                'url': image_url,
                'filename': filename
            })
        else:
            return jsonify({'error': 'فشل في حفظ الصورة'}), 500
            
    except Exception as e:
        return jsonify({'error': f'خطأ في الخادم: {str(e)}'}), 500

@app.route('/assets/images/<filename>')
def school_image(filename):
    return send_from_directory('assets/images', filename)

@app.route('/assets/materials/<filename>')
def material_file(filename):
    return send_from_directory('assets/materials', filename)

@app.route('/admin/observers', methods=['GET', 'POST'])
def admin_observers():
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    subjects = sorted(set(u.subject for u in User.query.all() if u.subject and u.subject.strip() != '-'))
    if request.method == 'POST':
        civil_id = request.form.get('civil_id')
        name = request.form.get('name')
        subject = request.form.get('subject')
        assignment = request.form.get('assignment')
        main_committee = request.form.get('main_committee')
        main_committee_other = request.form.get('main_committee_other')
        sub_committee = request.form.get('sub_committee')
        location = request.form.get('location')
        day = request.form.get('day')
        date = request.form.get('date')
        # معالجة اختيار أخرى في اللجنة الرئيسية فقط
        if main_committee == '__other__':
            if main_committee_other and main_committee_other.strip():
                main_committee = main_committee_other.strip()
            else:
                flash('يجب إدخال اللجنة الرئيسية الجديدة عند اختيار "أخرى..."', 'danger')
                return redirect(url_for('admin_observers'))
        if len(civil_id) != 12 or not civil_id.isdigit():
            flash('الرقم المدني يجب أن يكون 12 رقمًا', 'danger')
        elif Observer.query.filter_by(civil_id=civil_id).first():
            flash('يوجد ملاحظ مسجل بهذا الرقم المدني بالفعل', 'danger')
        elif not subject or not subject.strip():
            flash('يجب إدخال المادة', 'danger')
        elif not assignment or not assignment.strip():
            flash('يجب إدخال التكليف', 'danger')
        elif not main_committee or not main_committee.strip():
            flash('يجب اختيار أو إدخال اللجنة الرئيسية', 'danger')
        else:
            observer = Observer(
                civil_id=civil_id, name=name, subject=subject, assignment=assignment,
                main_committee=main_committee, sub_committee=sub_committee,
                location=location, day=day, date=date
            )
            db.session.add(observer)
            db.session.commit()
            
            # تسجيل العملية في سجل العمليات
            log_activity(
                operation_type='إضافة',
                table_name='observers',
                record_id=str(observer.id),
                new_data={
                    'id': observer.id,
                    'civil_id': civil_id,
                    'name': name,
                    'subject': subject,
                    'assignment': assignment,
                    'main_committee': main_committee,
                    'sub_committee': sub_committee,
                    'location': location,
                    'day': day,
                    'date': date
                },
                description=f'تم إضافة ملاحظ جديد: {name}'
            )
            
            flash('تمت إضافة الملاحظ بنجاح', 'success')
        return redirect(url_for('admin_observers'))
    observers = Observer.query.order_by(Observer.id.desc()).all()
    school_settings = get_school_settings()
    current_year = datetime.now().year
    return render_template('admin_observers.html', observers=observers, subjects=subjects, school_settings=school_settings, current_year=current_year)

@app.route('/admin/observers/edit/<int:observer_id>', methods=['GET', 'POST'])
def edit_observer(observer_id):
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    observer = Observer.query.get_or_404(observer_id)
    subjects = sorted(set(u.subject for u in User.query.all() if u.subject and u.subject.strip() != '-'))
    if request.method == 'POST':
        # حفظ البيانات القديمة قبل التعديل
        old_data = {
            'id': observer.id,
            'civil_id': observer.civil_id,
            'name': observer.name,
            'subject': observer.subject,
            'assignment': observer.assignment,
            'main_committee': observer.main_committee,
            'sub_committee': observer.sub_committee,
            'location': observer.location,
            'day': observer.day,
            'date': observer.date
        }
        
        observer.civil_id = request.form.get('civil_id')
        observer.name = request.form.get('name')
        observer.subject = request.form.get('subject')
        observer.assignment = request.form.get('assignment')
        observer.main_committee = request.form.get('main_committee')
        observer.sub_committee = request.form.get('sub_committee')
        observer.location = request.form.get('location')
        observer.day = request.form.get('day')
        observer.date = request.form.get('date')
        db.session.commit()
        
        # تسجيل العملية في سجل العمليات
        log_activity(
            operation_type='تعديل',
            table_name='observers',
            record_id=str(observer_id),
            old_data=old_data,
            new_data={
                'id': observer.id,
                'civil_id': observer.civil_id,
                'name': observer.name,
                'subject': observer.subject,
                'assignment': observer.assignment,
                'main_committee': observer.main_committee,
                'sub_committee': observer.sub_committee,
                'location': observer.location,
                'day': observer.day,
                'date': observer.date
            },
            description=f'تم تعديل بيانات الملاحظ: {observer.name}'
        )
        
        flash('تم تعديل بيانات الملاحظ بنجاح', 'success')
        return redirect(url_for('admin_observers'))
    school_settings = get_school_settings()
    current_year = datetime.now().year
    return render_template('edit_observer.html', observer=observer, subjects=subjects, school_settings=school_settings, current_year=current_year)

@app.route('/admin/observers/delete/<int:observer_id>', methods=['POST'])
def delete_observer(observer_id):
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    observer = Observer.query.get_or_404(observer_id)
    
    # حفظ بيانات الملاحظ قبل الحذف
    observer_data = {
        'id': observer.id,
        'civil_id': observer.civil_id,
        'name': observer.name,
        'subject': observer.subject,
        'assignment': observer.assignment,
        'main_committee': observer.main_committee,
        'sub_committee': observer.sub_committee,
        'location': observer.location,
        'day': observer.day,
        'date': observer.date
    }
    
    db.session.delete(observer)
    db.session.commit()
    
    # تسجيل العملية في سجل العمليات
    log_activity(
        operation_type='حذف',
        table_name='observers',
        record_id=str(observer_id),
        old_data=observer_data,
        description=f'تم حذف الملاحظ: {observer_data["name"]}'
    )
    
    flash('تم حذف الملاحظ بنجاح', 'success')
    return redirect(url_for('admin_observers'))

@app.route('/admin/observers/delete_all', methods=['POST'])
def delete_all_observers():
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    deleted = Observer.query.delete()
    db.session.commit()
    
    # تسجيل العملية في سجل العمليات
    log_activity(
        operation_type='حذف',
        table_name='observers',
        description=f'تم حذف جميع بيانات الملاحظين ({deleted} سجل)'
    )
    
    flash(f'تم حذف جميع بيانات الملاحظين ({deleted} سجل)', 'success')
    return redirect(url_for('admin_observers'))

@app.route('/admin/observers/upload', methods=['POST'])
def upload_observers():
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    file = request.files.get('excel_file')
    if not file:
        flash('يرجى اختيار ملف إكسل', 'danger')
        return redirect(url_for('admin_observers'))
    try:
        df = pd.read_excel(file, engine='openpyxl')
        required_cols = ['الرقم المدني', 'الاسم', 'المادة', 'التكليف', 'اللجنة الرئيسية', 'اللجنة الفرعية', 'موقع اللجنة', 'اليوم', 'التاريخ']
        if not all(col in df.columns for col in required_cols):
            flash('ملف الإكسل يجب أن يحتوي على الأعمدة: ' + ', '.join(required_cols), 'danger')
            return redirect(url_for('admin_observers'))
        added = 0
        for _, row in df.iterrows():
            civil_id = str(row['الرقم المدني']) if pd.notna(row['الرقم المدني']) and str(row['الرقم المدني']).strip() else '-'
            name = str(row['الاسم']) if pd.notna(row['الاسم']) and str(row['الاسم']).strip() else '-'
            subject = str(row['المادة']) if pd.notna(row['المادة']) and str(row['المادة']).strip() else '-'
            assignment = str(row['التكليف']) if pd.notna(row['التكليف']) and str(row['التكليف']).strip() else '-'
            main_committee = str(row['اللجنة الرئيسية']) if pd.notna(row['اللجنة الرئيسية']) and str(row['اللجنة الرئيسية']).strip() else '-'
            sub_committee = str(row['اللجنة الفرعية']) if pd.notna(row['اللجنة الفرعية']) and str(row['اللجنة الفرعية']).strip() else '-'
            location = str(row['موقع اللجنة']) if pd.notna(row['موقع اللجنة']) and str(row['موقع اللجنة']).strip() else '-'
            day = str(row['اليوم']) if pd.notna(row['اليوم']) and str(row['اليوم']).strip() else '-'
            date = str(row['التاريخ']) if pd.notna(row['التاريخ']) and str(row['التاريخ']).strip() else '-'
            if len(civil_id) == 12 and civil_id.isdigit() and not Observer.query.filter_by(civil_id=civil_id).first():
                observer = Observer(
                    civil_id=civil_id, name=name, subject=subject, assignment=assignment,
                    main_committee=main_committee, sub_committee=sub_committee,
                    location=location, day=day, date=date
                )
                db.session.add(observer)
                added += 1
        db.session.commit()
        
        # تسجيل العملية في سجل العمليات
        log_activity(
            operation_type='إضافة',
            table_name='observers',
            description=f'تم رفع ملف إكسل وإضافة {added} ملاحظ جديد'
        )
        
        flash(f'تمت إضافة {added} ملاحظ جديد', 'success')
    except Exception as e:
        flash('حدث خطأ أثناء معالجة الملف: ' + str(e), 'danger')
    return redirect(url_for('admin_observers'))

@app.route('/admin/observers/template')
def observers_template():
    import io
    output = io.BytesIO()
    import pandas as pd
    df = pd.DataFrame(columns=['الرقم المدني', 'الاسم', 'المادة', 'التكليف', 'اللجنة الرئيسية', 'اللجنة الفرعية', 'موقع اللجنة', 'اليوم', 'التاريخ'])
    df.to_excel(output, index=False, engine='openpyxl')
    output.seek(0)
    return send_file(output, as_attachment=True, download_name='observers_template.xlsx', mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

@app.route('/user/note')
def user_note():
    if 'civil_id' not in session:
        return redirect(url_for('login'))
    observer = Observer.query.filter_by(civil_id=session['civil_id']).first()
    school_settings = get_school_settings()
    current_year = datetime.now().year
    return render_template('user_observer.html', observer=observer, school_settings=school_settings, current_year=current_year)

@app.route('/user/inquiries', methods=['GET', 'POST'])
def user_inquiries():
    if 'civil_id' not in session or session['role'] != 'عادي':
        return redirect(url_for('login'))
    
    # التحقق من حالة تفعيل استفسارات المعلمين
    teacher_inquiries_enabled = get_system_setting('teacher_inquiries_enabled', '1')
    if teacher_inquiries_enabled != '1':
        flash('استفسارات المعلمين معطلة مؤقتاً من قبل الإدارة', 'warning')
        return redirect(url_for('user_dashboard'))
    
    user = User.query.filter_by(civil_id=session['civil_id']).first()
    if not user:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            # التحقق من رقم التليفون
            phone = request.form['phone'].strip()
            if not phone.isdigit() or len(phone) != 8:
                flash('يجب أن يكون رقم التليفون مكون من 8 أرقام فقط', 'danger')
                return redirect(url_for('user_inquiries'))
            
            # إنشاء استفسار جديد للمستخدم
            inquiry = Inquiry(
                student_civil_id=user.civil_id,  # استخدام الرقم المدني للمستخدم
                student_name=user.name,          # اسم المستخدم
                student_grade=user.subject,      # المادة في حقل student_grade
                student_section='-',             # لا يوجد شعبة للمستخدمين
                user_type=user.job_title if user.job_title else 'مستخدم',  # المسمى الوظيفي في حقل user_type
                message_type=request.form['message_type'],
                title=request.form['title'],
                message=request.form['message'],
                phone=phone,
                status='قيد المراجعة'
            )
            
            db.session.add(inquiry)
            db.session.commit()
            
            flash('تم إرسال الرسالة، شكرًا لتواصلك معنا', 'success')
            return redirect(url_for('user_inquiries'))
        except Exception as e:
            flash('حدث خطأ أثناء إرسال الرسالة. يرجى المحاولة مرة أخرى.', 'danger')
            return redirect(url_for('user_inquiries'))
    
    try:
        # تحديث حالة القراءة للاستفسارات المردود عليها
        Inquiry.query.filter_by(
            student_civil_id=user.civil_id,
            status='تم الرد',
            is_read=False
        ).update({'is_read': True})
        db.session.commit()
        
        # جلب استفسارات المستخدم
        inquiries = Inquiry.query.filter_by(student_civil_id=user.civil_id).order_by(Inquiry.submission_date.desc()).all()
        school_settings = get_school_settings()
        current_year = datetime.now().year
        return render_template('user_inquiries.html', user=user, inquiries=inquiries, school_settings=school_settings, current_year=current_year)
    except Exception as e:
        flash('حدث خطأ في عرض الاستفسارات. يرجى المحاولة مرة أخرى.', 'danger')
        school_settings = get_school_settings()
        current_year = datetime.now().year
        return render_template('user_inquiries.html', user=user, inquiries=[], school_settings=school_settings, current_year=current_year)

@app.route('/user_change_password', methods=['GET', 'POST'])
def user_change_password():
    if 'civil_id' not in session or session['role'] != 'عادي':
        return redirect(url_for('login'))
    user = User.query.filter_by(civil_id=session['civil_id']).first()
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        if not user or not check_password_hash(user.password, current_password):
            flash('كلمة المرور الحالية غير صحيحة', 'danger')
        elif new_password != confirm_password:
            flash('كلمة المرور الجديدة غير متطابقة مع التأكيد', 'danger')
        elif len(new_password) < 4:
            flash('كلمة المرور الجديدة يجب أن تكون 4 أحرف أو أكثر', 'danger')
        else:
            user.password = generate_password_hash(new_password)
            db.session.commit()
            flash('تم تغيير كلمة المرور بنجاح', 'success')
            return redirect(url_for('user_dashboard'))
    school_settings = get_school_settings()
    current_year = datetime.now().year
    return render_template('user_change_password.html', school_settings=school_settings, current_year=current_year)

@app.route('/student_login', methods=['GET', 'POST'])
def student_login():
    if request.method == 'POST':
        civil_id = request.form.get('civil_id')
        password = request.form.get('password')
        student = Student.query.filter_by(civil_id=civil_id).first()
        if student and student.password == password:
            session['student_civil_id'] = civil_id
            return redirect(url_for('student_home'))
        else:
            flash('الرقم المدني أو كلمة المرور غير صحيحة', 'danger')
    school_settings = get_school_settings()
    current_year = datetime.now().year
    return render_template('student_login.html', school_settings=school_settings, current_year=current_year)

@app.route('/student_home')
def student_home():
    if 'student_civil_id' not in session:
        return redirect(url_for('student_login'))
    try:
        student = Student.query.filter_by(civil_id=session['student_civil_id']).first()
        # حساب الاستفسارات غير المقروءة للطالب
        unread_inquiries_count = Inquiry.query.filter_by(
            student_civil_id=session['student_civil_id'],
            status='تم الرد',
            is_read=False
        ).count()
        # الحصول على حالة تفعيل استفسارات الطلاب
        student_inquiries_enabled = get_system_setting('student_inquiries_enabled', '1')
        school_settings = get_school_settings()
        current_year = datetime.now().year
        return render_template('student_home.html', student=student, unread_inquiries_count=unread_inquiries_count, student_inquiries_enabled=student_inquiries_enabled, school_settings=school_settings, current_year=current_year)
    except Exception as e:
        student = Student.query.filter_by(civil_id=session['student_civil_id']).first()
        student_inquiries_enabled = get_system_setting('student_inquiries_enabled', '1')
        school_settings = get_school_settings()
        current_year = datetime.now().year
        return render_template('student_home.html', student=student, unread_inquiries_count=0, student_inquiries_enabled=student_inquiries_enabled, school_settings=school_settings, current_year=current_year)

@app.route('/student_seat')
def student_seat():
    if 'student_civil_id' not in session:
        return redirect(url_for('student_login'))
    seat = Seat.query.filter_by(civil_id=session['student_civil_id']).first()
    school_settings = get_school_settings()
    current_year = datetime.now().year
    return render_template('student_seat.html', seat=seat, school_settings=school_settings, current_year=current_year)

@app.route('/student_change_password', methods=['GET', 'POST'])
def student_change_password():
    if 'student_civil_id' not in session:
        return redirect(url_for('student_login'))
    student = Student.query.filter_by(civil_id=session['student_civil_id']).first()
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        if not student or student.password != current_password:
            flash('كلمة المرور الحالية غير صحيحة', 'danger')
        elif new_password != confirm_password:
            flash('كلمة المرور الجديدة غير متطابقة مع التأكيد', 'danger')
        elif len(new_password) < 4:
            flash('كلمة المرور الجديدة يجب أن تكون 4 أحرف أو أكثر', 'danger')
        else:
            student.password = new_password
            db.session.commit()
            flash('تم تغيير كلمة المرور بنجاح', 'success')
            return redirect(url_for('student_home'))
    school_settings = get_school_settings()
    current_year = datetime.now().year
    return render_template('student_change_password.html', school_settings=school_settings, current_year=current_year)

@app.route('/student_materials')
def student_materials():
    if 'student_civil_id' not in session:
        return redirect(url_for('student_login'))
    
    student = Student.query.filter_by(civil_id=session['student_civil_id']).first()
    if not student:
        return redirect(url_for('student_login'))
    
    school_settings = get_school_settings()
    current_year = datetime.now().year
    return render_template('student_materials.html', student=student, school_settings=school_settings, current_year=current_year)

@app.route('/student_inquiries', methods=['GET', 'POST'])
def student_inquiries():
    if 'student_civil_id' not in session:
        return redirect(url_for('student_login'))
    
    # التحقق من حالة تفعيل استفسارات الطلاب
    student_inquiries_enabled = get_system_setting('student_inquiries_enabled', '1')
    if student_inquiries_enabled != '1':
        flash('استفسارات الطلاب معطلة مؤقتاً من قبل الإدارة', 'warning')
        return redirect(url_for('student_home'))
    
    student = Student.query.filter_by(civil_id=session['student_civil_id']).first()
    if not student:
        return redirect(url_for('student_login'))
    
    if request.method == 'POST':
        try:
            # التحقق من رقم التليفون
            phone = request.form['phone'].strip()
            if not phone.isdigit() or len(phone) != 8:
                flash('يجب أن يكون رقم التليفون مكون من 8 أرقام فقط', 'danger')
                return redirect(url_for('student_inquiries'))
            
            # إنشاء استفسار جديد
            inquiry = Inquiry(
                student_civil_id=student.civil_id,
                student_name=student.name,
                student_grade=student.grade,
                student_section=student.section,
                user_type='طالب',
                message_type=request.form['message_type'],
                title=request.form['title'],
                message=request.form['message'],
                phone=phone,
                status='قيد المراجعة'
            )
            
            db.session.add(inquiry)
            db.session.commit()
            
            flash('تم إرسال الرسالة، شكرًا لتواصلك معنا', 'success')
            return redirect(url_for('student_inquiries'))
        except Exception as e:
            flash('حدث خطأ أثناء إرسال الرسالة. يرجى المحاولة مرة أخرى.', 'danger')
            return redirect(url_for('student_inquiries'))
    
    try:
        # تحديث حالة القراءة للاستفسارات المردود عليها
        Inquiry.query.filter_by(
            student_civil_id=student.civil_id,
            status='تم الرد',
            is_read=False
        ).update({'is_read': True})
        db.session.commit()
        
        # جلب استفسارات الطالب
        inquiries = Inquiry.query.filter_by(student_civil_id=student.civil_id).order_by(Inquiry.submission_date.desc()).all()
        school_settings = get_school_settings()
        current_year = datetime.now().year
        return render_template('student_inquiries.html', student=student, inquiries=inquiries, school_settings=school_settings, current_year=current_year)
    except Exception as e:
        flash('حدث خطأ في عرض الاستفسارات. يرجى المحاولة مرة أخرى.', 'danger')
        school_settings = get_school_settings()
        current_year = datetime.now().year
        return render_template('student_inquiries.html', student=student, inquiries=[], school_settings=school_settings, current_year=current_year)

@app.route('/api/student_materials')
def api_student_materials():
    if 'student_civil_id' not in session:
        return {'error': 'غير مصرح'}, 401
    
    student = Student.query.filter_by(civil_id=session['student_civil_id']).first()
    if not student:
        return {'error': 'غير مصرح'}, 401
    
    # جلب المواد التعليمية للمرحلة المحددة للطالب فقط
    materials = EducationalMaterial.query.filter_by(stage=student.grade).order_by(EducationalMaterial.upload_date.desc()).all()
    
    # تحويل البيانات إلى JSON
    materials_data = []
    for material in materials:
        materials_data.append({
            'id': material.id,
            'stage': material.stage,
            'subject': material.subject,
            'title': material.title,
            'description': material.description,
            'material_type': material.material_type,
            'file_path': material.file_path,
            'video_url': material.video_url,
            'upload_date': material.upload_date.isoformat() if material.upload_date else None
        })
    
    return jsonify(materials_data)

@app.route('/admin/students', methods=['GET', 'POST'])
def admin_students():
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    if request.method == 'POST':
        civil_id = request.form.get('civil_id')
        name = request.form.get('name')
        grade = request.form.get('grade')
        section = request.form.get('section')
        password = request.form.get('password')
        if len(civil_id) != 12 or not civil_id.isdigit():
            flash('الرقم المدني يجب أن يكون 12 رقمًا', 'danger')
        elif Student.query.filter_by(civil_id=civil_id).first():
            flash('يوجد طالب مسجل بهذا الرقم المدني بالفعل', 'danger')
        else:
            student = Student(civil_id=civil_id, name=name, grade=grade, section=section, password=password)
            db.session.add(student)
            db.session.commit()
            
            # تسجيل العملية في سجل العمليات
            log_activity(
                operation_type='إضافة',
                table_name='students',
                record_id=civil_id,
                new_data={
                    'civil_id': civil_id,
                    'name': name,
                    'grade': grade,
                    'section': section
                },
                description=f'تم إضافة طالب جديد: {name}'
            )
            
            flash('تمت إضافة الطالب بنجاح', 'success')
        return redirect(url_for('admin_students'))
    students = Student.query.order_by(Student.name.asc()).all()
    school_settings = get_school_settings()
    current_year = datetime.now().year
    return render_template('admin_students.html', students=students, school_settings=school_settings, current_year=current_year)

@app.route('/admin/students/edit/<civil_id>', methods=['GET', 'POST'])
def edit_student(civil_id):
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    student = Student.query.get_or_404(civil_id)
    if request.method == 'POST':
        # حفظ البيانات القديمة قبل التعديل
        old_data = {
            'civil_id': student.civil_id,
            'name': student.name,
            'grade': student.grade,
            'section': student.section
        }
        
        student.name = request.form.get('name')
        student.grade = request.form.get('grade')
        student.section = request.form.get('section')
        student.password = request.form.get('password')
        db.session.commit()
        
        # تسجيل العملية في سجل العمليات
        log_activity(
            operation_type='تعديل',
            table_name='students',
            record_id=civil_id,
            old_data=old_data,
            new_data={
                'civil_id': student.civil_id,
                'name': student.name,
                'grade': student.grade,
                'section': student.section
            },
            description=f'تم تعديل بيانات الطالب: {student.name}'
        )
        
        flash('تم تعديل بيانات الطالب بنجاح', 'success')
        return redirect(url_for('admin_students'))
    students = Student.query.order_by(Student.name.asc()).all()
    school_settings = get_school_settings()
    current_year = datetime.now().year
    return render_template('admin_students.html', students=students, edit_student=student, school_settings=school_settings, current_year=current_year)

@app.route('/admin/students/delete/<civil_id>', methods=['POST'])
def delete_student(civil_id):
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    student = Student.query.get_or_404(civil_id)
    
    # حفظ بيانات الطالب قبل الحذف
    student_data = {
        'civil_id': student.civil_id,
        'name': student.name,
        'grade': student.grade,
        'section': student.section
    }
    
    db.session.delete(student)
    db.session.commit()
    
    # تسجيل العملية في سجل العمليات
    log_activity(
        operation_type='حذف',
        table_name='students',
        record_id=civil_id,
        old_data=student_data,
        description=f'تم حذف الطالب: {student_data["name"]}'
    )
    
    flash('تم حذف الطالب بنجاح', 'success')
    return redirect(url_for('admin_students'))

@app.route('/admin/students/delete_all', methods=['POST'])
def delete_all_students():
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    deleted = Student.query.delete()
    db.session.commit()
    
    # تسجيل العملية في سجل العمليات
    log_activity(
        operation_type='حذف',
        table_name='students',
        description=f'تم حذف جميع بيانات الطلاب ({deleted} سجل)'
    )
    
    flash(f'تم حذف جميع بيانات الطلاب ({deleted} سجل)', 'success')
    return redirect(url_for('admin_students'))

@app.route('/admin/students/upload', methods=['POST'])
def upload_students():
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    file = request.files.get('excel_file')
    if not file:
        flash('يرجى اختيار ملف إكسل', 'danger')
        return redirect(url_for('admin_students'))
    try:
        df = pd.read_excel(file, engine='openpyxl')
        required_cols = ['الرقم المدني', 'اسم الطالب', 'الصف', 'الشعبة', 'كلمة المرور']
        if not all(col in df.columns for col in required_cols):
            flash('ملف الإكسل يجب أن يحتوي على الأعمدة: ' + ', '.join(required_cols), 'danger')
            return redirect(url_for('admin_students'))
        added = 0
        invalid_students = []
        for _, row in df.iterrows():
            civil_id = str(row['الرقم المدني']) if pd.notna(row['الرقم المدني']) and str(row['الرقم المدني']).strip() else '-'
            name = str(row['اسم الطالب']) if pd.notna(row['اسم الطالب']) and str(row['اسم الطالب']).strip() else '-'
            grade = str(row['الصف']) if pd.notna(row['الصف']) and str(row['الصف']).strip() else '-'
            section = str(row['الشعبة']) if pd.notna(row['الشعبة']) and str(row['الشعبة']).strip() else '-'
            password = str(row['كلمة المرور']) if pd.notna(row['كلمة المرور']) and str(row['كلمة المرور']).strip() else '-'
            if len(civil_id) == 12 and civil_id.isdigit() and not Student.query.filter_by(civil_id=civil_id).first():
                student = Student(civil_id=civil_id, name=name, grade=grade, section=section, password=password)
                db.session.add(student)
                added += 1
            else:
                if civil_id != '-' and (len(civil_id) != 12 or not civil_id.isdigit()):
                    invalid_students.append({'name': name, 'civil_id': civil_id, 'grade': grade, 'section': section})
        db.session.commit()
        
        # تسجيل العملية في سجل العمليات
        log_activity(
            operation_type='إضافة',
            table_name='students',
            description=f'تم رفع ملف إكسل وإضافة {added} طالب جديد'
        )
        
        flash(f'تمت إضافة {added} طالب جديد', 'success')
        if invalid_students:
            report = '''
            <div dir="rtl" class="my-4">
                <div class="font-bold text-red-700 mb-2">الطلاب الذين لم يتم إضافتهم بسبب الرقم المدني غير صحيح (يجب أن يكون 12 رقم):</div>
                <div class="overflow-x-auto">
                    <table class="min-w-[320px] max-w-full bg-white border border-red-300 rounded text-xs md:text-base my-2 text-right">
                        <thead class="bg-red-100">
                            <tr>
                                <th class="px-4 py-2 border-b">اسم الطالب</th>
                                <th class="px-4 py-2 border-b">الرقم المدني</th>
                                <th class="px-4 py-2 border-b">الصف</th>
                                <th class="px-4 py-2 border-b">الشعبة</th>
                            </tr>
                        </thead>
                        <tbody>
            '''
            for s in invalid_students:
                report += f'<tr><td class="px-4 py-2 border-b">{s["name"]}</td><td class="px-4 py-2 border-b">{s["civil_id"]}</td><td class="px-4 py-2 border-b">{s.get("grade", "-")}</td><td class="px-4 py-2 border-b">{s.get("section", "-")}</td></tr>'
            report += '''
                        </tbody>
                    </table>
                </div>
            </div>
            '''
            flash(report, 'danger')
    except Exception as e:
        flash('حدث خطأ أثناء معالجة الملف: ' + str(e), 'danger')
    return redirect(url_for('admin_students'))

@app.route('/admin/students/template')
def students_template():
    import io
    output = io.BytesIO()
    import pandas as pd
    from openpyxl import Workbook
    from openpyxl.utils.dataframe import dataframe_to_rows
    
    # إنشاء DataFrame فارغ
    df = pd.DataFrame(columns=['الرقم المدني', 'اسم الطالب', 'الصف', 'الشعبة', 'كلمة المرور'])
    
    # إنشاء ملف Excel باستخدام openpyxl
    wb = Workbook()
    ws = wb.active
    
    # إضافة العناوين
    for r in dataframe_to_rows(df, index=False, header=True):
        ws.append(r)
    
    # إضافة المعادلة في أول خلية من عمود كلمة المرور (العمود E)
    ws['E2'] = '=RANDBETWEEN(3001, 9999)'
    
    # حفظ الملف
    wb.save(output)
    output.seek(0)
    
    return send_file(output, as_attachment=True, download_name='students_template.xlsx', mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

@app.route('/admin/subjects', methods=['GET', 'POST'])
def admin_subjects():
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    if request.method == 'POST':
        stage = request.form.get('stage')
        subject_name = request.form.get('subject')
        if not stage or not subject_name:
            flash('يجب اختيار المرحلة وكتابة اسم المادة', 'danger')
        elif Subject.query.filter_by(stage=stage, subject=subject_name).first():
            flash('هذه المادة مسجلة بالفعل لهذه المرحلة', 'danger')
        else:
            s = Subject(stage=stage, subject=subject_name)
            db.session.add(s)
            db.session.commit()
            
            # تسجيل العملية
            log_activity(
                operation_type='إضافة',
                table_name='subjects',
                record_id=str(s.id),
                new_data={
                    'id': s.id,
                    'stage': s.stage,
                    'subject': s.subject
                },
                description=f'إضافة مادة جديدة: {s.subject} للمرحلة {s.stage}'
            )
            
            flash('تمت إضافة المادة بنجاح', 'success')
        return redirect(url_for('admin_subjects'))
    subjects = Subject.query.order_by(Subject.stage, Subject.subject).all()
    school_settings = get_school_settings()
    current_year = datetime.now().year
    return render_template('admin_subjects.html', subjects=subjects, school_settings=school_settings, current_year=current_year)

@app.route('/admin/subjects/edit/<int:subject_id>', methods=['GET', 'POST'])
def edit_subject(subject_id):
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    subject = Subject.query.get_or_404(subject_id)
    if request.method == 'POST':
        stage = request.form.get('stage')
        subject_name = request.form.get('subject')
        if not stage or not subject_name:
            flash('يجب اختيار المرحلة وكتابة اسم المادة', 'danger')
        elif Subject.query.filter(Subject.stage==stage, Subject.subject==subject_name, Subject.id!=subject_id).first():
            flash('هذه المادة مسجلة بالفعل لهذه المرحلة', 'danger')
        else:
            # تسجيل البيانات القديمة قبل التعديل
            old_data = {
                'id': subject.id,
                'stage': subject.stage,
                'subject': subject.subject
            }
            
            subject.stage = stage
            subject.subject = subject_name
            db.session.commit()
            
            # تسجيل العملية
            log_activity(
                operation_type='تعديل',
                table_name='subjects',
                record_id=str(subject_id),
                old_data=old_data,
                new_data={
                    'id': subject.id,
                    'stage': subject.stage,
                    'subject': subject.subject
                },
                description=f'تعديل مادة: {old_data["subject"]} إلى {subject.subject}'
            )
            
            flash('تم تعديل المادة بنجاح', 'success')
            return redirect(url_for('admin_subjects'))
    school_settings = get_school_settings()
    current_year = datetime.now().year
    return render_template('edit_subject.html', subject=subject, school_settings=school_settings, current_year=current_year)

@app.route('/admin/subjects/delete/<int:subject_id>', methods=['POST'])
def delete_subject(subject_id):
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    subject = Subject.query.get_or_404(subject_id)
    
    # تسجيل البيانات القديمة قبل الحذف
    old_data = {
        'id': subject.id,
        'stage': subject.stage,
        'subject': subject.subject
    }
    
    db.session.delete(subject)
    db.session.commit()
    
    # تسجيل العملية
    log_activity(
        operation_type='حذف',
        table_name='subjects',
        record_id=str(subject_id),
        old_data=old_data,
        description=f'حذف مادة: {old_data["subject"]}'
    )
    
    flash('تم حذف المادة بنجاح', 'success')
    return redirect(url_for('admin_subjects'))

@app.route('/admin/upload_materials', methods=['GET', 'POST'])
def admin_upload_materials():
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        stage = request.form.get('stage')
        subject = request.form.get('subject')
        title = request.form.get('title')
        description = request.form.get('description')
        material_type = request.form.get('material_type')
        
        if not all([stage, subject, title, material_type]):
            flash('يجب ملء جميع الحقول المطلوبة', 'danger')
            return redirect(url_for('admin_upload_materials'))
        
        # التحقق من نوع المادة
        if material_type == 'PDF':
            if 'file' not in request.files or request.files['file'].filename == '':
                flash('يجب رفع ملف PDF', 'danger')
                return redirect(url_for('admin_upload_materials'))
            
            file = request.files['file']
            if file and file.filename.endswith('.pdf'):
                # حفظ الملف
                filename = f"material_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
                file_path = os.path.join('assets', 'materials', filename)
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                file.save(file_path)
                
                material = EducationalMaterial(
                    stage=stage,
                    subject=subject,
                    title=title,
                    description=description,
                    material_type='PDF',
                    file_path=filename  # حفظ اسم الملف فقط
                )
                db.session.add(material)
                db.session.commit()
                
                # تسجيل العملية في سجل العمليات
                log_activity(
                    operation_type='إضافة',
                    table_name='educational_materials',
                    record_id=str(material.id),
                    new_data={
                        'id': material.id,
                        'stage': stage,
                        'subject': subject,
                        'title': title,
                        'description': description,
                        'material_type': 'PDF',
                        'file_path': filename
                    },
                    description=f'تم رفع مادة تعليمية جديدة: {title}'
                )
                
                flash('تم رفع المادة التعليمية بنجاح', 'success')
            else:
                flash('يجب رفع ملف PDF صحيح', 'danger')
        
        elif material_type == 'فيديو':
            video_url = request.form.get('video_url')
            if not video_url:
                flash('يجب إدخال رابط الفيديو', 'danger')
                return redirect(url_for('admin_upload_materials'))
            
            material = EducationalMaterial(
                stage=stage,
                subject=subject,
                title=title,
                description=description,
                material_type='فيديو',
                video_url=video_url
            )
            db.session.add(material)
            db.session.commit()
            
            # تسجيل العملية في سجل العمليات
            log_activity(
                operation_type='إضافة',
                table_name='educational_materials',
                record_id=str(material.id),
                new_data={
                    'id': material.id,
                    'stage': stage,
                    'subject': subject,
                    'title': title,
                    'description': description,
                    'material_type': 'فيديو',
                    'video_url': video_url
                },
                description=f'تم رفع مادة تعليمية جديدة: {title}'
            )
            
            flash('تم رفع المادة التعليمية بنجاح', 'success')
        
        return redirect(url_for('admin_upload_materials'))
    
    # تجميع البيانات للمواد حسب المرحلة
    subjects_data = {}
    subjects = Subject.query.all()
    for subject in subjects:
        if subject.stage not in subjects_data:
            subjects_data[subject.stage] = []
        subjects_data[subject.stage].append(subject.subject)
    
    # جلب المواد المرفوعة
    materials = EducationalMaterial.query.order_by(EducationalMaterial.upload_date.desc()).all()
    
    school_settings = get_school_settings()
    current_year = datetime.now().year
    return render_template('admin_upload_materials.html', subjects_data=subjects_data, materials=materials, school_settings=school_settings, current_year=current_year)

@app.route('/admin/upload_materials/delete/<int:material_id>', methods=['POST'])
def delete_material(material_id):
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    
    material = EducationalMaterial.query.get_or_404(material_id)
    
    # تسجيل البيانات القديمة قبل الحذف
    old_data = {
        'id': material.id,
        'stage': material.stage,
        'subject': material.subject,
        'title': material.title,
        'description': material.description,
        'material_type': material.material_type,
        'file_path': material.file_path,
        'video_url': material.video_url,
        'upload_date': material.upload_date.isoformat() if material.upload_date else None
    }
    
    # حذف الملف إذا كان موجود
    if material.material_type == 'PDF' and material.file_path:
        try:
            # تنظيف المسار - إزالة التكرار
            if material.file_path.startswith('assets/materials/'):
                file_path = material.file_path
            else:
                file_path = os.path.join('assets', 'materials', material.file_path)
            
            if os.path.exists(file_path):
                os.remove(file_path)
        except:
            pass  # تجاهل الأخطاء في حذف الملف
    
    db.session.delete(material)
    db.session.commit()
    
    # تسجيل العملية
    log_activity(
        operation_type='حذف',
        table_name='educational_materials',
        record_id=material_id,
        old_data=old_data,
        description=f'حذف مادة تعليمية: {old_data["title"]}'
    )
    
    flash('تم حذف المادة التعليمية بنجاح', 'success')
    return redirect(url_for('admin_upload_materials'))

@app.route('/admin/upload_materials/delete_all', methods=['POST'])
def delete_all_materials():
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    
    try:
        # الحصول على عدد المواد قبل الحذف
        materials_count = EducationalMaterial.query.count()
        
        # حذف جميع الملفات المرفوعة أولاً
        materials = EducationalMaterial.query.filter_by(material_type='PDF').all()
        for material in materials:
            if material.file_path:
                try:
                    # تنظيف المسار - إزالة التكرار
                    if material.file_path.startswith('assets/materials/'):
                        file_path = material.file_path
                    else:
                        file_path = os.path.join('assets', 'materials', material.file_path)
                    
                    if os.path.exists(file_path):
                        os.remove(file_path)
                except:
                    pass  # تجاهل الأخطاء في حذف الملف
        
        # حذف جميع المواد من قاعدة البيانات
        EducationalMaterial.query.delete()
        db.session.commit()
        
        # تسجيل العملية
        log_activity(
            operation_type='حذف',
            table_name='educational_materials',
            old_data={'count': materials_count},
            description=f'حذف جميع المواد التعليمية ({materials_count} مادة)'
        )
        
        flash('تم حذف جميع المواد التعليمية بنجاح', 'success')
    except Exception as e:
        db.session.rollback()
        flash('حدث خطأ أثناء حذف المواد التعليمية', 'danger')
    
    return redirect(url_for('admin_upload_materials'))

@app.route('/admin/fix_material_paths')
def fix_material_paths():
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    
    materials = EducationalMaterial.query.filter_by(material_type='PDF').all()
    fixed_count = 0
    
    for material in materials:
        if material.file_path and 'assets/materials/' in material.file_path:
            # استخراج اسم الملف فقط
            filename = material.file_path.split('/')[-1]
            material.file_path = filename
            fixed_count += 1
    
    if fixed_count > 0:
        db.session.commit()
        flash(f'تم تصحيح {fixed_count} مسار ملف', 'success')
    else:
        flash('لا توجد مسارات تحتاج تصحيح', 'info')
    
    return redirect(url_for('admin_upload_materials'))

@app.route('/admin/fix_database')
def fix_database():
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    
    try:
        from sqlalchemy import text
        
        # التحقق من وجود جدول inquiry
        result = db.session.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name='inquiry'"))
        if not result.fetchone():
            # إنشاء الجدول إذا لم يكن موجود
            db.create_all()
            flash('تم إنشاء جميع الجداول المطلوبة بنجاح', 'success')
            return redirect(url_for('admin_dashboard'))
        
        # التحقق من وجود عمود student_section في جدول inquiry
        result = db.session.execute(text("PRAGMA table_info(inquiry)"))
        columns = [row[1] for row in result.fetchall()]
        
        fixed_columns = []
        
        if 'student_section' not in columns:
            # إضافة العمود المفقود
            db.session.execute(text("ALTER TABLE inquiry ADD COLUMN student_section VARCHAR(10)"))
            fixed_columns.append('student_section')
        
        # التحقق من وجود أعمدة أخرى قد تكون مفقودة
        required_columns = {
            'student_civil_id': 'VARCHAR(20)',
            'student_name': 'VARCHAR(100)',
            'student_grade': 'VARCHAR(20)',
            'user_type': 'VARCHAR(20)',
            'message_type': 'VARCHAR(20)',
            'title': 'VARCHAR(200)',
            'message': 'TEXT',
            'phone': 'VARCHAR(20)',
            'status': 'VARCHAR(20)',
            'response': 'TEXT',
            'is_read': 'BOOLEAN',
            'submission_date': 'DATETIME',
            'last_updated': 'DATETIME'
        }
        
        # إنشاء جدول الأنشطة المدرسية إذا لم يكن موجود
        result = db.session.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name='school_activity'"))
        if not result.fetchone():
            db.create_all()
            flash('تم إنشاء جدول الأنشطة المدرسية بنجاح', 'success')
        
        for col_name, col_type in required_columns.items():
            if col_name not in columns:
                db.session.execute(text(f"ALTER TABLE inquiry ADD COLUMN {col_name} {col_type}"))
                fixed_columns.append(col_name)
        
        # التحقق من وجود الأعمدة الجديدة في جدول school_settings وإضافتها إذا لم تكن موجودة
        try:
            # التحقق من وجود جدول school_settings
            result = db.session.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name='school_settings'"))
            if result.fetchone():
                # التحقق من أعمدة الجدول
                result = db.session.execute(text("PRAGMA table_info(school_settings)"))
                school_settings_columns = [row[1] for row in result.fetchall()]
                
                if 'academic_year' not in school_settings_columns:
                    db.session.execute(text("ALTER TABLE school_settings ADD COLUMN academic_year VARCHAR(50)"))
                    fixed_columns.append('school_settings_academic_year')
                    print("تم إضافة عمود academic_year")
                
                if 'academic_semester' not in school_settings_columns:
                    db.session.execute(text("ALTER TABLE school_settings ADD COLUMN academic_semester VARCHAR(50)"))
                    fixed_columns.append('school_settings_academic_semester')
                    print("تم إضافة عمود academic_semester")
            else:
                # إنشاء الجدول إذا لم يكن موجود
                db.create_all()
                fixed_columns.append('create_school_settings_table')
                print("تم إنشاء جدول school_settings")
        except Exception as e:
            print(f"خطأ في التحقق من جدول school_settings: {e}")
            # محاولة إنشاء الجدول إذا لم يكن موجود
            try:
                db.create_all()
                fixed_columns.append('create_school_settings_table')
                print("تم إنشاء جدول school_settings")
            except Exception as create_error:
                print(f"خطأ في إنشاء الجدول: {create_error}")
        
        # إنشاء إعدادات افتراضية للاستفسارات إذا لم تكن موجودة
        settings_to_create = [
            ('student_inquiries_enabled', '1', 'تفعيل استفسارات الطلاب'),
            ('teacher_inquiries_enabled', '1', 'تفعيل استفسارات المعلمين')
        ]
        
        for setting_key, default_value, description in settings_to_create:
            if not SystemSettings.query.filter_by(setting_key=setting_key).first():
                default_setting = SystemSettings(
                    setting_key=setting_key,
                    setting_value=default_value,
                    description=description
                )
                db.session.add(default_setting)
                fixed_columns.append(f'system_settings_{setting_key}')
        
        # إنشاء إعدادات افتراضية للمدرسة إذا لم تكن موجودة
        try:
            if not SchoolSettings.query.first():
                default_school_settings = SchoolSettings(
                    school_name='مدرسة الواحة',
                    school_address='',
                    school_phone='',
                    school_email='',
                    school_vision='',
                    school_mission='',
                    school_values='',
                    google_maps_url='',
                    youtube_url='',
                    instagram_url='',
                    telegram_url='',
                    snapchat_url='',
                    whatsapp_url='',
                    academic_year='2024-2025',
                    academic_semester='الفصل الدراسي الأول'
                )
                db.session.add(default_school_settings)
                fixed_columns.append('school_settings')
        except Exception as e:
            print(f"خطأ في إنشاء إعدادات المدرسة الافتراضية: {e}")
            # محاولة إنشاء الجدول إذا لم يكن موجود
            try:
                db.create_all()
                fixed_columns.append('create_school_settings_table')
            except Exception as create_error:
                print(f"خطأ في إنشاء الجدول: {create_error}")
        
        if fixed_columns:
            db.session.commit()
            flash(f'تم إصلاح قاعدة البيانات بنجاح. الأعمدة المضافة: {", ".join(fixed_columns)}', 'success')
        else:
            flash('قاعدة البيانات محدثة بالفعل ولا تحتاج إصلاح', 'info')
            
    except Exception as e:
        flash(f'حدث خطأ أثناء إصلاح قاعدة البيانات: {str(e)}', 'danger')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/fix_school_settings')
def fix_school_settings():
    """دالة خاصة لإصلاح جدول إعدادات المدرسة"""
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    
    try:
        from sqlalchemy import text
        
        # حفظ البيانات الموجودة
        existing_data = None
        try:
            result = db.session.execute(text("SELECT * FROM school_settings LIMIT 1"))
            row = result.fetchone()
            if row:
                # حفظ البيانات الموجودة
                existing_data = {
                    'school_logo': row[1] if len(row) > 1 else None,
                    'school_name': row[2] if len(row) > 2 else 'مدرسة الواحة',
                    'school_address': row[3] if len(row) > 3 else '',
                    'school_phone': row[4] if len(row) > 4 else '',
                    'school_email': row[5] if len(row) > 5 else '',
                    'school_vision': row[6] if len(row) > 6 else '',
                    'school_mission': row[7] if len(row) > 7 else '',
                    'school_values': row[8] if len(row) > 8 else '',
                    'google_maps_url': row[9] if len(row) > 9 else '',
                    'youtube_url': row[10] if len(row) > 10 else '',
                    'instagram_url': row[11] if len(row) > 11 else '',
                    'telegram_url': row[12] if len(row) > 12 else '',
                    'snapchat_url': row[13] if len(row) > 13 else '',
                    'whatsapp_url': row[14] if len(row) > 14 else ''
                }
        except Exception as e:
            print(f"خطأ في قراءة البيانات الموجودة: {e}")
        
        # حذف الجدول القديم
        try:
            db.session.execute(text("DROP TABLE IF EXISTS school_settings"))
            db.session.commit()
            print("تم حذف الجدول القديم")
        except Exception as e:
            print(f"خطأ في حذف الجدول: {e}")
        
        # إنشاء الجدول الجديد
        db.create_all()
        print("تم إنشاء الجدول الجديد")
        
        # إعادة إدخال البيانات مع الحقول الجديدة
        if existing_data:
            new_settings = SchoolSettings(
                school_logo=existing_data['school_logo'],
                school_name=existing_data['school_name'],
                school_address=existing_data['school_address'],
                school_phone=existing_data['school_phone'],
                school_email=existing_data['school_email'],
                school_vision=existing_data['school_vision'],
                school_mission=existing_data['school_mission'],
                school_values=existing_data['school_values'],
                google_maps_url=existing_data['google_maps_url'],
                youtube_url=existing_data['youtube_url'],
                instagram_url=existing_data['instagram_url'],
                telegram_url=existing_data['telegram_url'],
                snapchat_url=existing_data['snapchat_url'],
                whatsapp_url=existing_data['whatsapp_url'],
                academic_year='2024-2025',
                academic_semester='الفصل الدراسي الأول'
            )
        else:
            # إنشاء إعدادات افتراضية جديدة
            new_settings = SchoolSettings(
                school_name='مدرسة الواحة',
                school_address='',
                school_phone='',
                school_email='',
                school_vision='',
                school_mission='',
                school_values='',
                google_maps_url='',
                youtube_url='',
                instagram_url='',
                telegram_url='',
                snapchat_url='',
                whatsapp_url='',
                academic_year='2024-2025',
                academic_semester='الفصل الدراسي الأول'
            )
        
        db.session.add(new_settings)
        db.session.commit()
        
        flash('تم إعادة إنشاء جدول إعدادات المدرسة بنجاح مع الحقول الجديدة! ✅', 'success')
            
    except Exception as e:
        db.session.rollback()
        flash(f'حدث خطأ أثناء إعادة إنشاء جدول إعدادات المدرسة: {str(e)}', 'danger')
    
    return redirect(url_for('admin_settings'))

@app.route('/admin/test_database')
def test_database():
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    
    try:
        from sqlalchemy import text
        
        # اختبار الاتصال بقاعدة البيانات
        db.session.execute(text("SELECT 1"))
        
        # التحقق من وجود جدول inquiry
        result = db.session.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name='inquiry'"))
        if not result.fetchone():
            flash('جدول inquiry غير موجود في قاعدة البيانات', 'warning')
            return redirect(url_for('admin_dashboard'))
        
        # التحقق من وجود الأعمدة المطلوبة
        result = db.session.execute(text("PRAGMA table_info(inquiry)"))
        columns = [row[1] for row in result.fetchall()]
        
        missing_columns = []
        required_columns = ['student_section', 'student_civil_id', 'student_name', 'student_grade']
        
        for col in required_columns:
            if col not in columns:
                missing_columns.append(col)
        
        if missing_columns:
            flash(f'الأعمدة التالية مفقودة في جدول inquiry: {", ".join(missing_columns)}', 'warning')
        else:
            flash('قاعدة البيانات تعمل بشكل صحيح', 'success')
            
    except Exception as e:
        flash(f'خطأ في الاتصال بقاعدة البيانات: {str(e)}', 'danger')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/create_school_settings_table')
def create_school_settings_table():
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    
    try:
        # إنشاء جميع الجداول
        db.create_all()
        
        # التحقق من وجود الأعمدة الجديدة وإضافتها إذا لم تكن موجودة
        try:
            result = db.session.execute(text("PRAGMA table_info(school_settings)"))
            columns = [row[1] for row in result.fetchall()]
            
            # إضافة الأعمدة الجديدة إذا لم تكن موجودة
            if 'academic_year' not in columns:
                db.session.execute(text("ALTER TABLE school_settings ADD COLUMN academic_year VARCHAR(50)"))
                flash('تم إضافة عمود العام الدراسي', 'success')
            
            if 'academic_semester' not in columns:
                db.session.execute(text("ALTER TABLE school_settings ADD COLUMN academic_semester VARCHAR(50)"))
                flash('تم إضافة عمود الفصل الدراسي', 'success')
        except Exception as e:
            print(f"خطأ في التحقق من أعمدة الجدول: {e}")
        
        # إنشاء إعدادات افتراضية للمدرسة
        if not SchoolSettings.query.first():
            default_school_settings = SchoolSettings(
                school_name='مدرسة الواحة',
                school_address='',
                school_phone='',
                school_email='',
                school_vision='',
                school_mission='',
                school_values='',
                google_maps_url='',
                youtube_url='',
                instagram_url='',
                telegram_url='',
                snapchat_url='',
                whatsapp_url='',
                academic_year='2024-2025',
                academic_semester='الفصل الدراسي الأول'
            )
            db.session.add(default_school_settings)
            db.session.commit()
            flash('تم إنشاء جدول إعدادات المدرسة بنجاح! ✅', 'success')
        else:
            # تحديث الإعدادات الموجودة بالقيم الافتراضية للحقول الجديدة
            existing_settings = SchoolSettings.query.first()
            if not existing_settings.academic_year:
                existing_settings.academic_year = '2024-2025'
            if not existing_settings.academic_semester:
                existing_settings.academic_semester = 'الفصل الدراسي الأول'
            db.session.commit()
            flash('تم تحديث جدول إعدادات المدرسة بنجاح! ✅', 'success')
            
    except Exception as e:
        db.session.rollback()
        flash(f'حدث خطأ أثناء إنشاء الجدول: {str(e)}', 'danger')
    
    return redirect(url_for('admin_settings'))

@app.route('/admin/create_activity_log_table')
def create_activity_log_table():
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    
    try:
        # إنشاء جدول سجل العمليات
        db.create_all()
        flash('تم إنشاء جدول سجل العمليات بنجاح! ✅', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'حدث خطأ أثناء إنشاء الجدول: {str(e)}', 'danger')
    
    return redirect(url_for('admin_settings'))

@app.route('/admin/activity_log')
def admin_activity_log():
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    
    try:
        page = request.args.get('page', 1, type=int)
        operation_filter = request.args.get('operation', '')
        table_filter = request.args.get('table', '')
        user_filter = request.args.get('user', '')
        date_filter = request.args.get('date', '')
        
        # بناء الاستعلام
        query = ActivityLog.query
        
        if operation_filter:
            query = query.filter(ActivityLog.operation_type == operation_filter)
        if table_filter:
            query = query.filter(ActivityLog.table_name == table_filter)
        if user_filter:
            query = query.filter(
                db.or_(
                    ActivityLog.user_name.contains(user_filter),
                    ActivityLog.user_civil_id.contains(user_filter)
                )
            )
        if date_filter:
            # تحويل التاريخ إلى datetime للبحث
            try:
                filter_date = datetime.strptime(date_filter, '%Y-%m-%d')
                next_date = filter_date.replace(hour=23, minute=59, second=59)
                query = query.filter(
                    db.and_(
                        ActivityLog.created_at >= filter_date,
                        ActivityLog.created_at <= next_date
                    )
                )
            except ValueError:
                pass  # تجاهل التاريخ إذا كان غير صحيح
        
        # ترتيب حسب التاريخ (الأحدث أولاً)
        query = query.order_by(ActivityLog.created_at.desc())
        
        # ترقيم الصفحات
        logs = query.paginate(page=page, per_page=50, error_out=False)
        
        # قوائم الفلترة
        operations = db.session.query(ActivityLog.operation_type).distinct().all()
        operations = [op[0] for op in operations]
        
        tables = db.session.query(ActivityLog.table_name).distinct().all()
        tables = [table[0] for table in tables]
        
        users = db.session.query(ActivityLog.user_name).distinct().all()
        users = [user[0] for user in users if user[0]]
        
        school_settings = get_school_settings()
        return render_template('admin_activity_log.html', 
                             logs=logs, 
                             operations=operations, 
                             tables=tables, 
                             users=users,
                             school_settings=school_settings)
                             
    except Exception as e:
        flash(f'حدث خطأ أثناء تحميل سجل العمليات: {str(e)}', 'danger')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/activity_log/<int:log_id>/details')
def get_activity_log_details(log_id):
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return jsonify({'error': 'غير مصرح'}), 403
    
    try:
        log = ActivityLog.query.get_or_404(log_id)
        
        # تحويل البيانات من JSON إلى dict
        old_data = json.loads(log.old_data) if log.old_data else None
        new_data = json.loads(log.new_data) if log.new_data else None
        
        # تنسيق البيانات للعرض
        details = {
            'id': log.id,
            'operation_type': log.operation_type,
            'table_name': log.table_name,
            'record_id': log.record_id,
            'user_info': {
                'civil_id': log.user_civil_id,
                'name': log.user_name,
                'subject': log.user_subject,
                'job_title': log.user_job_title
            },
            'description': log.description,
            'ip_address': log.ip_address,
            'user_agent': log.user_agent,
            'created_at': log.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'old_data': old_data,
            'new_data': new_data
        }
        
        return jsonify(details)
        
    except Exception as e:
        return jsonify({'error': f'حدث خطأ: {str(e)}'}), 500

@app.route('/admin/activity_log/clear_all', methods=['POST'])
def clear_all_activity_logs():
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return jsonify({'success': False, 'message': 'غير مصرح'}), 403
    
    try:
        # حذف جميع السجلات من جدول activity_log
        deleted_count = ActivityLog.query.delete()
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': f'تم مسح {deleted_count} سجل بنجاح'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False, 
            'message': f'حدث خطأ أثناء مسح السجلات: {str(e)}'
        }), 500

@app.route('/admin/inquiries')
def admin_inquiries():
    if 'role' in session and (session['role'] == 'مشرف' or session['role'] == 'مشرف محتوى'):
        try:
            page = request.args.get('page', 1, type=int)
            status_filter = request.args.get('status', '')
            type_filter = request.args.get('type', '')
            user_type_filter = request.args.get('user_type', '')
            grade_filter = request.args.get('grade', '')
            section_filter = request.args.get('section', '')
            search_filter = request.args.get('search', '')
            
            # بناء الاستعلام
            query = Inquiry.query
            
            if status_filter:
                query = query.filter(Inquiry.status == status_filter)
            if type_filter:
                query = query.filter(Inquiry.message_type == type_filter)
            if user_type_filter:
                query = query.filter(Inquiry.user_type == user_type_filter)
            if grade_filter:
                query = query.filter(Inquiry.student_grade == grade_filter)
            if section_filter:
                query = query.filter(Inquiry.student_section == section_filter)
            if search_filter:
                query = query.filter(
                    db.or_(
                        Inquiry.title.contains(search_filter),
                        Inquiry.message.contains(search_filter),
                        Inquiry.student_name.contains(search_filter)
                    )
                )
            
            # ترتيب حسب التاريخ (الأحدث أولاً)
            query = query.order_by(Inquiry.submission_date.desc())
            
            # ترقيم الصفحات
            inquiries = query.paginate(page=page, per_page=20, error_out=False)
            
            # إحصائيات
            total_inquiries = Inquiry.query.count()
            pending_inquiries = Inquiry.query.filter_by(status='قيد المراجعة').count()
            responded_inquiries = Inquiry.query.filter_by(status='تم الرد').count()
            unique_students = db.session.query(db.func.count(db.distinct(Inquiry.student_civil_id))).scalar()
            
            # قائمة الصفوف والشعب وأنواع المستخدمين للفلتر
            grades = db.session.query(Inquiry.student_grade).distinct().all()
            grades = [grade[0] for grade in grades]
            
            sections = db.session.query(Inquiry.student_section).distinct().all()
            sections = [section[0] for section in sections]
            
            user_types = db.session.query(Inquiry.user_type).distinct().all()
            user_types = [user_type[0] for user_type in user_types]
            
            # الحصول على حالة تفعيل الاستفسارات
            student_inquiries_enabled = get_system_setting('student_inquiries_enabled', '1')
            teacher_inquiries_enabled = get_system_setting('teacher_inquiries_enabled', '1')
            
            school_settings = get_school_settings()
            current_year = datetime.now().year
            return render_template('admin_inquiries.html', 
                                 inquiries=inquiries,
                                 total_inquiries=total_inquiries,
                                 pending_inquiries=pending_inquiries,
                                 responded_inquiries=responded_inquiries,
                                 unique_students=unique_students,
                                 grades=grades,
                                 sections=sections,
                                 user_types=user_types,
                                 student_inquiries_enabled=student_inquiries_enabled,
                                 teacher_inquiries_enabled=teacher_inquiries_enabled,
                                 school_settings=school_settings,
                                 current_year=current_year)
        except Exception as e:
            # إذا كان هناك خطأ في قاعدة البيانات، عرض رسالة للمشرف
            flash('يوجد مشكلة في قاعدة البيانات. يرجى الضغط على زر "إصلاح قاعدة البيانات" في لوحة التحكم لحل المشكلة.', 'warning')
            return redirect(url_for('admin_dashboard'))
    else:
        flash('ليس لديك صلاحية للوصول لهذه الصفحة', 'danger')
        return redirect(url_for('login'))

@app.route('/admin/inquiries/<int:inquiry_id>')
def get_inquiry(inquiry_id):
    if 'role' in session and (session['role'] == 'مشرف' or session['role'] == 'مشرف محتوى'):
        try:
            inquiry = Inquiry.query.get_or_404(inquiry_id)
            return jsonify({
                'id': inquiry.id,
                'student_name': inquiry.student_name,
                'student_grade': inquiry.student_grade,
                'student_section': inquiry.student_section,
                'message_type': inquiry.message_type,
                'title': inquiry.title,
                'message': inquiry.message,
                'phone': inquiry.phone,
                'status': inquiry.status,
                'response': inquiry.response,
                'submission_date': inquiry.submission_date.strftime('%Y-%m-%d %H:%M'),
                'last_updated': inquiry.last_updated.strftime('%Y-%m-%d %H:%M') if inquiry.response else None
            })
        except Exception as e:
            return jsonify({'error': 'خطأ في قاعدة البيانات'}), 500
    else:
        return jsonify({'error': 'غير مصرح'}), 403

@app.route('/admin/inquiries/<int:inquiry_id>/respond', methods=['POST'])
def respond_to_inquiry(inquiry_id):
    if 'role' in session and (session['role'] == 'مشرف' or session['role'] == 'مشرف محتوى'):
        try:
            inquiry = Inquiry.query.get_or_404(inquiry_id)
            response_text = request.form.get('response', '').strip()
            
            if response_text:
                inquiry.response = response_text
                inquiry.status = 'تم الرد'
                inquiry.is_read = False  # تعيين كغير مقروء عند الرد
                inquiry.last_updated = datetime.utcnow()
                
                db.session.commit()
                flash('تم إرسال الرد بنجاح', 'success')
            else:
                flash('يرجى كتابة رد', 'danger')
        except Exception as e:
            flash('حدث خطأ أثناء حفظ الرد. يرجى التأكد من إصلاح قاعدة البيانات.', 'danger')
    else:
        flash('ليس لديك صلاحية للوصول لهذه الصفحة', 'danger')
    
    return redirect(url_for('admin_inquiries'))

@app.route('/admin/inquiries/delete_all', methods=['POST'])
def delete_all_inquiries():
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    
    try:
        # الحصول على عدد الاستفسارات قبل الحذف
        inquiries_count = Inquiry.query.count()
        
        # حذف جميع الاستفسارات من قاعدة البيانات
        Inquiry.query.delete()
        db.session.commit()
        
        # تسجيل العملية
        log_activity(
            operation_type='حذف',
            table_name='inquiries',
            old_data={'count': inquiries_count},
            description=f'حذف جميع الاستفسارات والشكاوى ({inquiries_count} استفسار)'
        )
        
        flash('تم حذف جميع الاستفسارات والشكاوى بنجاح', 'success')
    except Exception as e:
        db.session.rollback()
        flash('حدث خطأ أثناء حذف الاستفسارات', 'danger')
    
    return redirect(url_for('admin_inquiries'))

@app.route('/admin/inquiries/toggle_student_feature', methods=['POST'])
def toggle_student_inquiries_feature():
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    
    try:
        action = request.form.get('action')
        if action == 'enable':
            set_system_setting('student_inquiries_enabled', '1', 'تفعيل استفسارات الطلاب')
            flash('تم تفعيل استفسارات الطلاب بنجاح! 🎉', 'success')
        elif action == 'disable':
            set_system_setting('student_inquiries_enabled', '0', 'إلغاء تفعيل استفسارات الطلاب')
            flash('تم إلغاء تفعيل استفسارات الطلاب بنجاح! 🔒', 'success')
        else:
            flash('إجراء غير صحيح', 'danger')
    except Exception as e:
        flash('حدث خطأ أثناء تحديث الإعدادات', 'danger')
    
    return redirect(url_for('admin_inquiries'))

@app.route('/admin/inquiries/toggle_teacher_feature', methods=['POST'])
def toggle_teacher_inquiries_feature():
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    
    try:
        action = request.form.get('action')
        if action == 'enable':
            set_system_setting('teacher_inquiries_enabled', '1', 'تفعيل استفسارات المعلمين')
            flash('تم تفعيل استفسارات المعلمين بنجاح! 🎉', 'success')
        elif action == 'disable':
            set_system_setting('teacher_inquiries_enabled', '0', 'إلغاء تفعيل استفسارات المعلمين')
            flash('تم إلغاء تفعيل استفسارات المعلمين بنجاح! 🔒', 'success')
        else:
            flash('إجراء غير صحيح', 'danger')
    except Exception as e:
        flash('حدث خطأ أثناء تحديث الإعدادات', 'danger')
    
    return redirect(url_for('admin_inquiries'))

@app.route('/admin/settings', methods=['GET', 'POST'])
def admin_settings():
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    
    try:
        # الحصول على إعدادات المدرسة الحالية
        try:
            school_settings = SchoolSettings.query.first()
        except Exception as e:
            print(f"خطأ في قراءة إعدادات المدرسة: {e}")
            # إذا كان هناك خطأ، توجيه المستخدم لإصلاح قاعدة البيانات
            flash('يبدو أن هناك مشكلة في قاعدة البيانات. يرجى الضغط على زر "إصلاح جدول الإعدادات" أدناه.', 'danger')
            return render_template('admin_settings.html', school_settings=None)
        
        if request.method == 'POST':
            # معالجة رفع الشعار
            logo_file = request.files.get('school_logo')
            logo_filename = None
            
            if logo_file and logo_file.filename:
                try:
                    # التأكد من وجود مجلد الصور
                    images_dir = os.path.join('assets', 'images')
                    if not os.path.exists(images_dir):
                        os.makedirs(images_dir)
                    
                    # حفظ الشعار الجديد
                    logo_filename = secure_filename(logo_file.filename)
                    logo_path = os.path.join(images_dir, logo_filename)
                    logo_file.save(logo_path)
                    
                    # حذف الشعار القديم إذا كان موجود
                    if school_settings and school_settings.school_logo:
                        old_logo_path = os.path.join(images_dir, school_settings.school_logo)
                        if os.path.exists(old_logo_path) and old_logo_path != logo_path:
                            os.remove(old_logo_path)
                except Exception as file_error:
                    print(f"خطأ في معالجة الملف: {file_error}")
                    flash(f'خطأ في معالجة الصورة: {str(file_error)}', 'danger')
                    return render_template('admin_settings.html', school_settings=school_settings)
            elif school_settings:
                logo_filename = school_settings.school_logo
            
            try:
                # تحديث أو إنشاء إعدادات المدرسة
                if school_settings:
                    school_settings.school_logo = logo_filename
                    school_settings.school_name = request.form.get('school_name', '')
                    school_settings.school_address = request.form.get('school_address', '')
                    school_settings.school_phone = request.form.get('school_phone', '')
                    school_settings.school_email = request.form.get('school_email', '')
                    school_settings.school_vision = request.form.get('school_vision', '')
                    school_settings.school_mission = request.form.get('school_mission', '')
                    school_settings.school_values = request.form.get('school_values', '')
                    school_settings.google_maps_url = request.form.get('google_maps_url', '')
                    school_settings.youtube_url = request.form.get('youtube_url', '')
                    school_settings.instagram_url = request.form.get('instagram_url', '')
                    school_settings.telegram_url = request.form.get('telegram_url', '')
                    school_settings.snapchat_url = request.form.get('snapchat_url', '')
                    school_settings.whatsapp_url = request.form.get('whatsapp_url', '')
                    school_settings.academic_year = request.form.get('academic_year', '')
                    school_settings.academic_semester = request.form.get('academic_semester', '')
                else:
                    school_settings = SchoolSettings(
                        school_logo=logo_filename,
                        school_name=request.form.get('school_name', ''),
                        school_address=request.form.get('school_address', ''),
                        school_phone=request.form.get('school_phone', ''),
                        school_email=request.form.get('school_email', ''),
                        school_vision=request.form.get('school_vision', ''),
                        school_mission=request.form.get('school_mission', ''),
                        school_values=request.form.get('school_values', ''),
                        google_maps_url=request.form.get('google_maps_url', ''),
                        youtube_url=request.form.get('youtube_url', ''),
                        instagram_url=request.form.get('instagram_url', ''),
                        telegram_url=request.form.get('telegram_url', ''),
                        snapchat_url=request.form.get('snapchat_url', ''),
                        whatsapp_url=request.form.get('whatsapp_url', ''),
                        academic_year=request.form.get('academic_year', ''),
                        academic_semester=request.form.get('academic_semester', '')
                    )
                    db.session.add(school_settings)
                
                db.session.commit()
                flash('تم حفظ إعدادات المدرسة بنجاح! ✅', 'success')
                return redirect(url_for('admin_settings'))
                
            except Exception as db_error:
                db.session.rollback()
                print(f"خطأ في قاعدة البيانات: {db_error}")
                flash(f'خطأ في حفظ البيانات: {str(db_error)}', 'danger')
                return render_template('admin_settings.html', school_settings=school_settings)
        
        return render_template('admin_settings.html', school_settings=school_settings)
        
    except Exception as e:
        print(f"خطأ عام: {e}")
        flash(f'حدث خطأ أثناء حفظ الإعدادات: {str(e)}', 'danger')
        return render_template('admin_settings.html', school_settings=school_settings)

@app.route('/admin/activities', methods=['GET', 'POST'])
def admin_activities():
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            name = request.form.get('name')
            description = request.form.get('description')
            activity_date = request.form.get('activity_date')
            media_type = request.form.get('media_type')
            
            if not all([name, description, activity_date, media_type]):
                flash('يرجى ملء جميع الحقول المطلوبة', 'danger')
                return redirect(url_for('admin_activities'))
            
            # التحقق من الملف
            if 'file' not in request.files or request.files['file'].filename == '':
                flash('يرجى اختيار ملف', 'danger')
                return redirect(url_for('admin_activities'))
            
            file = request.files['file']
            
            # التحقق من نوع الملف
            allowed_image_extensions = {'jpg', 'jpeg', 'png'}
            allowed_video_extensions = {'mp4'}
            
            if media_type == 'صورة':
                if not file.filename.lower().endswith(tuple('.' + ext for ext in allowed_image_extensions)):
                    flash('يرجى رفع ملف صورة بصيغة JPEG أو PNG', 'danger')
                    return redirect(url_for('admin_activities'))
            elif media_type == 'فيديو':
                if not file.filename.lower().endswith('.mp4'):
                    flash('يرجى رفع ملف فيديو بصيغة MP4', 'danger')
                    return redirect(url_for('admin_activities'))
            
            # حفظ الملف
            import os
            from werkzeug.utils import secure_filename
            
            # إنشاء مجلد الأنشطة إذا لم يكن موجود
            activities_dir = os.path.join('assets', 'activities')
            os.makedirs(activities_dir, exist_ok=True)
            
            # إنشاء اسم فريد للملف
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"activity_{timestamp}_{secure_filename(file.filename)}"
            file_path = os.path.join(activities_dir, filename)
            
            file.save(file_path)
            
            # إنشاء صورة مصغرة للفيديو إذا كان نوع الوسائط فيديو
            thumbnail_path = None
            if media_type == 'فيديو':
                try:
                    # فتح الفيديو
                    video = cv2.VideoCapture(file_path)
                    if video.isOpened():
                        # أخذ الإطار الأول (أو الإطار في الثانية 1)
                        video.set(cv2.CAP_PROP_POS_MSEC, 1000)  # ثانية واحدة
                        ret, frame = video.read()
                        if ret:
                            # حفظ الصورة المصغرة
                            thumbnail_filename = f"thumb_{timestamp}_{secure_filename(file.filename)}.jpg"
                            thumbnail_path = os.path.join(activities_dir, thumbnail_filename)
                            cv2.imwrite(thumbnail_path, frame)
                            thumbnail_path = thumbnail_filename
                        video.release()
                except Exception as e:
                    print(f"خطأ في إنشاء الصورة المصغرة: {e}")
                    thumbnail_path = None
            
            # إنشاء نشاط جديد
            activity = SchoolActivity(
                name=name,
                description=description,
                activity_date=datetime.strptime(activity_date, '%Y-%m-%d').date(),
                upload_date=datetime.utcnow()
            )
            
            db.session.add(activity)
            db.session.flush()  # للحصول على ID النشاط
            
            # إنشاء سجل الوسائط
            activity_media = ActivityMedia(
                activity_id=activity.id,
                media_type=media_type,
                file_path=filename,
                file_name=file.filename,
                thumbnail_path=thumbnail_path,
                is_primary=True,
                display_order=0
            )
            
            db.session.add(activity_media)
            db.session.commit()
            
            # تسجيل العملية
            log_activity(
                operation_type='إضافة',
                table_name='school_activities',
                record_id=str(activity.id),
                new_data={
                    'id': activity.id,
                    'name': activity.name,
                    'description': activity.description,
                    'activity_date': activity.activity_date.isoformat(),
                    'media_type': media_type,
                    'file_path': filename,
                    'upload_date': activity.upload_date.isoformat() if activity.upload_date else None
                },
                description=f'إضافة نشاط جديد: {activity.name}'
            )
            
            flash('تم رفع النشاط بنجاح', 'success')
            return redirect(url_for('admin_activities'))
            
        except Exception as e:
            flash(f'حدث خطأ أثناء رفع النشاط: {str(e)}', 'danger')
            return redirect(url_for('admin_activities'))
    
    # جلب الأنشطة مع الوسائط المرتبطة
    try:
        query = SchoolActivity.query
        activities = query.order_by(SchoolActivity.activity_date.desc()).all()
        
        # جلب الوسائط لكل نشاط
        for activity in activities:
            activity.media = ActivityMedia.query.filter_by(activity_id=activity.id).order_by(ActivityMedia.display_order).all()
        
        school_settings = get_school_settings()
        current_year = datetime.now().year
        return render_template('admin_activities.html', activities=activities, school_settings=school_settings, current_year=current_year)
        
    except Exception as e:
        flash(f'حدث خطأ في عرض الأنشطة: {str(e)}', 'danger')
        school_settings = get_school_settings()
        current_year = datetime.now().year
        return render_template('admin_activities.html', activities=[], school_settings=school_settings, current_year=current_year)

@app.route('/admin/activities/delete/<int:activity_id>', methods=['POST'])
def delete_activity(activity_id):
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    
    try:
        activity = SchoolActivity.query.get_or_404(activity_id)
        
        # تسجيل البيانات القديمة قبل الحذف
        old_data = {
            'id': activity.id,
            'name': activity.name,
            'description': activity.description,
            'activity_date': activity.activity_date.isoformat(),
            'upload_date': activity.upload_date.isoformat() if activity.upload_date else None
        }
        
        # حذف جميع الوسائط المرتبطة
        media_list = ActivityMedia.query.filter_by(activity_id=activity_id).all()
        for media in media_list:
            # حذف الملف من الخادم
            file_path = os.path.join('assets', 'activities', media.file_path)
            if os.path.exists(file_path):
                os.remove(file_path)
            
            # حذف الصورة المصغرة إذا كانت موجودة
            if media.thumbnail_path:
                thumbnail_path = os.path.join('assets', 'activities', media.thumbnail_path)
                if os.path.exists(thumbnail_path):
                    os.remove(thumbnail_path)
        
        # حذف النشاط (سيحذف الوسائط تلقائياً بسبب cascade)
        db.session.delete(activity)
        db.session.commit()
        
        # تسجيل العملية
        log_activity(
            operation_type='حذف',
            table_name='school_activities',
            record_id=str(activity_id),
            old_data=old_data,
            description=f'حذف نشاط: {old_data["name"]} مع {len(media_list)} ملفات'
        )
        
        flash('تم حذف النشاط بنجاح', 'success')
        
    except Exception as e:
        flash(f'حدث خطأ أثناء حذف النشاط: {str(e)}', 'danger')
    
    return redirect(url_for('admin_activities'))

@app.route('/admin/activities/delete_all', methods=['POST'])
def delete_all_activities():
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return redirect(url_for('login'))
    
    try:
        # جلب جميع الأنشطة
        activities = SchoolActivity.query.all()
        activities_count = len(activities)
        total_media_count = 0
        import os
        
        # حذف جميع الوسائط من الخادم
        for activity in activities:
            media_list = ActivityMedia.query.filter_by(activity_id=activity.id).all()
            total_media_count += len(media_list)
            
            for media in media_list:
                # حذف الملف الرئيسي
                file_path = os.path.join('assets', 'activities', media.file_path)
                if os.path.exists(file_path):
                    os.remove(file_path)
                
                # حذف الصورة المصغرة إذا كانت موجودة
                if media.thumbnail_path:
                    thumbnail_path = os.path.join('assets', 'activities', media.thumbnail_path)
                    if os.path.exists(thumbnail_path):
                        os.remove(thumbnail_path)
        
        # حذف جميع الأنشطة من قاعدة البيانات (سيحذف الوسائط تلقائياً)
        SchoolActivity.query.delete()
        db.session.commit()
        
        # تسجيل العملية
        log_activity(
            operation_type='حذف',
            table_name='school_activities',
            old_data={'count': activities_count, 'media_count': total_media_count},
            description=f'حذف جميع الأنشطة ({activities_count} نشاط) مع {total_media_count} ملف'
        )
        
        flash('تم حذف جميع الأنشطة بنجاح', 'success')
        
    except Exception as e:
        flash(f'حدث خطأ أثناء حذف الأنشطة: {str(e)}', 'danger')
    
    return redirect(url_for('admin_activities'))

@app.route('/assets/activities/<filename>')
def activity_file(filename):
    return send_from_directory('assets/activities', filename)

@app.route('/activities')
def activities_gallery():
    """صفحة معرض الأنشطة للزوار"""
    try:
        # جلب الأنشطة مع الوسائط المرتبطة
        query = SchoolActivity.query
        activities = query.order_by(SchoolActivity.activity_date.desc()).all()
        
        # جلب الوسائط لكل نشاط
        for activity in activities:
            activity.media = ActivityMedia.query.filter_by(activity_id=activity.id).order_by(ActivityMedia.display_order).all()
        
        school_settings = get_school_settings()
        current_year = datetime.now().year
        
        return render_template('activities_gallery.html', activities=activities, school_settings=school_settings, current_year=current_year)
        
    except Exception as e:
        flash(f'حدث خطأ في عرض الأنشطة: {str(e)}', 'danger')
        school_settings = get_school_settings()
        current_year = datetime.now().year
        return render_template('activities_gallery.html', activities=[], school_settings=school_settings, current_year=current_year)

@app.route('/mark_inquiry_read/<int:inquiry_id>', methods=['POST'])
def mark_inquiry_read(inquiry_id):
    """تحديث حالة القراءة للاستفسار"""
    try:
        inquiry = Inquiry.query.get_or_404(inquiry_id)
        
        # التحقق من أن المستخدم يملك هذا الاستفسار
        if 'civil_id' in session:
            if inquiry.student_civil_id == session['civil_id']:
                inquiry.is_read = True
                db.session.commit()
                return jsonify({'success': True})
        elif 'student_civil_id' in session:
            if inquiry.student_civil_id == session['student_civil_id']:
                inquiry.is_read = True
                db.session.commit()
                return jsonify({'success': True})
        
        return jsonify({'error': 'غير مصرح'}), 403
    except Exception as e:
        return jsonify({'error': 'خطأ في قاعدة البيانات'}), 500

# مسارات التقويم المدرسي
@app.route('/calendar')
def school_calendar():
    school_settings = get_school_settings()
    current_year = datetime.now().year
    return render_template('school_calendar.html', school_settings=school_settings, current_year=current_year)

@app.route('/api/calendar/events')
def get_calendar_events():
    """الحصول على جميع أحداث التقويم"""
    events = CalendarEvent.query.all()
    events_data = []
    
    for event in events:
        events_data.append({
            'id': event.id,
            'title': event.title,
            'start': event.start_date.strftime('%Y-%m-%d'),
            'end': event.end_date.strftime('%Y-%m-%d'),
            'type': event.event_type,
            'time': event.event_time,
            'location': event.location,
            'description': event.description
        })
    
    return jsonify(events_data)

@app.route('/api/calendar/events', methods=['POST'])
def create_calendar_event():
    """إنشاء حدث جديد في التقويم"""
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return jsonify({'error': 'غير مصرح، يجب أن تكون مشرفاً لإضافة أحداث'}), 403
    
    data = request.get_json()
    
    try:
        new_event = CalendarEvent(
            title=data['title'],
            event_type=data['type'],
            start_date=datetime.strptime(data['start'], '%Y-%m-%d').date(),
            end_date=datetime.strptime(data['end'], '%Y-%m-%d').date(),
            event_time=data.get('time'),
            location=data.get('location'),
            description=data.get('description')
        )
        
        db.session.add(new_event)
        db.session.commit()
        
        # تسجيل العملية
        log_activity(
            operation_type='إضافة',
            table_name='calendar_events',
            record_id=str(new_event.id),
            new_data={
                'id': new_event.id,
                'title': new_event.title,
                'event_type': new_event.event_type,
                'start_date': new_event.start_date.isoformat(),
                'end_date': new_event.end_date.isoformat(),
                'event_time': new_event.event_time,
                'location': new_event.location,
                'description': new_event.description,
                'created_at': new_event.created_at.isoformat() if new_event.created_at else None,
                'updated_at': new_event.updated_at.isoformat() if new_event.updated_at else None
            },
            description=f'إضافة حدث جديد في التقويم: {new_event.title}'
        )
        
        return jsonify({
            'success': True,
            'message': 'تم إضافة الحدث بنجاح',
            'event': {
                'id': new_event.id,
                'title': new_event.title,
                'start': new_event.start_date.strftime('%Y-%m-%d'),
                'end': new_event.end_date.strftime('%Y-%m-%d'),
                'type': new_event.event_type,
                'time': new_event.event_time,
                'location': new_event.location,
                'description': new_event.description
            }
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/api/calendar/events/<int:event_id>', methods=['PUT'])
def update_calendar_event(event_id):
    """تحديث حدث في التقويم"""
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return jsonify({'error': 'غير مصرح، يجب أن تكون مشرفاً لتعديل الأحداث'}), 403
    
    event = CalendarEvent.query.get_or_404(event_id)
    data = request.get_json()
    
    try:
        # تسجيل البيانات القديمة قبل التعديل
        old_data = {
            'id': event.id,
            'title': event.title,
            'event_type': event.event_type,
            'start_date': event.start_date.isoformat(),
            'end_date': event.end_date.isoformat(),
            'event_time': event.event_time,
            'location': event.location,
            'description': event.description,
            'created_at': event.created_at.isoformat() if event.created_at else None,
            'updated_at': event.updated_at.isoformat() if event.updated_at else None
        }
        
        event.title = data['title']
        event.event_type = data['type']
        event.start_date = datetime.strptime(data['start'], '%Y-%m-%d').date()
        event.end_date = datetime.strptime(data['end'], '%Y-%m-%d').date()
        event.event_time = data.get('time')
        event.location = data.get('location')
        event.description = data.get('description')
        event.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        # تسجيل العملية
        log_activity(
            operation_type='تعديل',
            table_name='calendar_events',
            record_id=str(event_id),
            old_data=old_data,
            new_data={
                'id': event.id,
                'title': event.title,
                'event_type': event.event_type,
                'start_date': event.start_date.isoformat(),
                'end_date': event.end_date.isoformat(),
                'event_time': event.event_time,
                'location': event.location,
                'description': event.description,
                'created_at': event.created_at.isoformat() if event.created_at else None,
                'updated_at': event.updated_at.isoformat() if event.updated_at else None
            },
            description=f'تعديل حدث في التقويم: {old_data["title"]} إلى {event.title}'
        )
        
        return jsonify({
            'success': True,
            'message': 'تم تحديث الحدث بنجاح'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/api/school/settings')
def get_school_settings_api():
    """الحصول على إعدادات المدرسة كـ JSON"""
    school_settings = get_school_settings()
    return jsonify({
        'school_name': school_settings.school_name,
        'school_address': school_settings.school_address,
        'school_phone': school_settings.school_phone,
        'school_email': school_settings.school_email,
        'academic_year': school_settings.academic_year,
        'academic_semester': school_settings.academic_semester
    })

@app.route('/api/calendar/events/<int:event_id>', methods=['DELETE'])
def delete_calendar_event(event_id):
    """حذف حدث من التقويم"""
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return jsonify({'error': 'غير مصرح، يجب أن تكون مشرفاً لحذف الأحداث'}), 403
    
    event = CalendarEvent.query.get_or_404(event_id)
    
    try:
        # تسجيل البيانات القديمة قبل الحذف
        old_data = {
            'id': event.id,
            'title': event.title,
            'event_type': event.event_type,
            'start_date': event.start_date.isoformat(),
            'end_date': event.end_date.isoformat(),
            'event_time': event.event_time,
            'location': event.location,
            'description': event.description,
            'created_at': event.created_at.isoformat() if event.created_at else None,
            'updated_at': event.updated_at.isoformat() if event.updated_at else None
        }
        
        db.session.delete(event)
        db.session.commit()
        
        # تسجيل العملية
        log_activity(
            operation_type='حذف',
            table_name='calendar_events',
            record_id=str(event_id),
            old_data=old_data,
            description=f'حذف حدث من التقويم: {old_data["title"]}'
        )
        
        return jsonify({
            'success': True,
            'message': 'تم حذف الحدث بنجاح'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/admin/activities/upload_multiple', methods=['POST'])
def upload_multiple_activity_files():
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return jsonify({'success': False, 'message': 'غير مصرح لك بهذه العملية'})
    
    try:
        # التحقق من البيانات المطلوبة
        name = request.form.get('name')
        description = request.form.get('description')
        activity_date = request.form.get('activity_date')
        
        if not all([name, description, activity_date]):
            return jsonify({'success': False, 'message': 'يرجى ملء جميع الحقول المطلوبة'})
        
        # التحقق من الملفات
        if 'files[]' not in request.files:
            return jsonify({'success': False, 'message': 'يرجى اختيار ملفات'})
        
        files = request.files.getlist('files[]')
        if not files or all(file.filename == '' for file in files):
            return jsonify({'success': False, 'message': 'يرجى اختيار ملفات صحيحة'})
        
        # التحقق من أنواع الملفات
        allowed_image_extensions = {'jpg', 'jpeg', 'png'}
        allowed_video_extensions = {'mp4', 'avi', 'mov'}
        
        uploaded_files = []
        for file in files:
            if file.filename == '':
                continue
                
            file_extension = file.filename.rsplit('.', 1)[1].lower()
            
            # تحديد نوع الوسائط
            if file_extension in allowed_image_extensions:
                media_type = 'صورة'
            elif file_extension in allowed_video_extensions:
                media_type = 'فيديو'
            else:
                return jsonify({'success': False, 'message': f'نوع الملف {file.filename} غير مدعوم'})
            
            uploaded_files.append({
                'file': file,
                'media_type': media_type,
                'original_name': file.filename
            })
        
        # إنشاء النشاط
        activity = SchoolActivity(
            name=name,
            description=description,
            activity_date=datetime.strptime(activity_date, '%Y-%m-%d').date()
        )
        
        db.session.add(activity)
        db.session.flush()  # للحصول على ID النشاط
        
        # إنشاء مجلد الأنشطة إذا لم يكن موجود
        activities_dir = os.path.join('assets', 'activities')
        os.makedirs(activities_dir, exist_ok=True)
        
        # حفظ الملفات
        for index, file_data in enumerate(uploaded_files):
            file = file_data['file']
            media_type = file_data['media_type']
            original_name = file_data['original_name']
            
            # إنشاء اسم فريد للملف
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"activity_{activity.id}_{timestamp}_{index}_{secure_filename(original_name)}"
            file_path = os.path.join(activities_dir, filename)
            
            file.save(file_path)
            
            # ضغط الصور
            if media_type == 'صورة':
                try:
                    compress_image(file_path)
                except Exception as e:
                    print(f"خطأ في ضغط الصورة: {e}")
            
            # إنشاء صورة مصغرة للفيديو
            thumbnail_path = None
            if media_type == 'فيديو':
                try:
                    video = cv2.VideoCapture(file_path)
                    if video.isOpened():
                        video.set(cv2.CAP_PROP_POS_MSEC, 1000)
                        ret, frame = video.read()
                        if ret:
                            thumbnail_filename = f"thumb_{activity.id}_{timestamp}_{index}.jpg"
                            thumbnail_path = os.path.join(activities_dir, thumbnail_filename)
                            cv2.imwrite(thumbnail_path, frame)
                            thumbnail_path = thumbnail_filename
                        video.release()
                except Exception as e:
                    print(f"خطأ في إنشاء الصورة المصغرة: {e}")
            
            # إنشاء سجل الوسائط
            activity_media = ActivityMedia(
                activity_id=activity.id,
                media_type=media_type,
                file_path=filename,
                file_name=original_name,
                thumbnail_path=thumbnail_path,
                is_primary=(index == 0),  # أول ملف يكون رئيسي
                display_order=index
            )
            
            db.session.add(activity_media)
        
        db.session.commit()
        
        # تسجيل العملية
        log_activity(
            operation_type='إضافة',
            table_name='school_activities',
            record_id=str(activity.id),
            new_data={
                'id': activity.id,
                'name': activity.name,
                'description': activity.description,
                'activity_date': activity.activity_date.isoformat(),
                'media_count': len(uploaded_files),
                'upload_date': activity.upload_date.isoformat() if activity.upload_date else None
            },
            description=f'إضافة نشاط جديد: {activity.name} مع {len(uploaded_files)} ملفات'
        )
        
        return jsonify({
            'success': True, 
            'message': f'تم رفع النشاط بنجاح مع {len(uploaded_files)} ملفات',
            'activity_id': activity.id
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'حدث خطأ أثناء رفع النشاط: {str(e)}'})

@app.route('/admin/activities/reorder_media', methods=['POST'])
def reorder_activity_media():
    print("=== بداية reorder_activity_media ===")
    
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        print("خطأ في الصلاحيات")
        return jsonify({'success': False, 'message': 'غير مصرح لك بهذه العملية'})
    
    try:
        data = request.get_json()
        print("البيانات المستلمة:", data)
        
        activity_id = int(data.get('activity_id')) if data.get('activity_id') else None
        media_order = data.get('media_order', [])  # قائمة بترتيب معرفات الوسائط
        primary_media_id = int(data.get('primary_media_id')) if data.get('primary_media_id') else None
        
        print("activity_id:", activity_id)
        print("media_order:", media_order)
        print("primary_media_id:", primary_media_id)
        
        if not activity_id:
            print("معرف النشاط مفقود")
            return jsonify({'success': False, 'message': 'معرف النشاط مطلوب'})
        
        # التحقق من وجود النشاط
        activity = SchoolActivity.query.get(activity_id)
        if not activity:
            print("النشاط غير موجود")
            return jsonify({'success': False, 'message': 'النشاط غير موجود'})
        
        print("النشاط موجود:", activity.name)
        
        # إعادة ترتيب الوسائط
        updated_count = 0
        for index, media_id in enumerate(media_order):
            media_id = int(media_id) if media_id else None
            if not media_id:
                continue
                
            media = ActivityMedia.query.get(media_id)
            if media and media.activity_id == activity_id:
                print(f"تحديث الوسائط {media_id}: display_order={index}, is_primary={media_id == primary_media_id}")
                media.display_order = index
                # تعيين الوسائط كرئيسية أو غير رئيسية
                if media_id == primary_media_id:
                    media.is_primary = True
                else:
                    media.is_primary = False
                updated_count += 1
        
        print(f"تم تحديث {updated_count} وسائط")
        
        db.session.commit()
        print("تم حفظ التغييرات في قاعدة البيانات")
        
        return jsonify({'success': True, 'message': 'تم تحديث ترتيب الوسائط بنجاح'})
        
    except Exception as e:
        print("خطأ في reorder_activity_media:", str(e))
        db.session.rollback()
        return jsonify({'success': False, 'message': f'حدث خطأ: {str(e)}'})

@app.route('/admin/activities/delete_media/<int:media_id>', methods=['POST'])
def delete_activity_media(media_id):
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        return jsonify({'success': False, 'message': 'غير مصرح لك بهذه العملية'})
    
    try:
        media = ActivityMedia.query.get_or_404(media_id)
        activity_id = media.activity_id
        
        # حذف الملف من الخادم
        file_path = os.path.join('assets', 'activities', media.file_path)
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # حذف الصورة المصغرة إذا كانت موجودة
        if media.thumbnail_path:
            thumbnail_path = os.path.join('assets', 'activities', media.thumbnail_path)
            if os.path.exists(thumbnail_path):
                os.remove(thumbnail_path)
        
        db.session.delete(media)
        db.session.commit()
        
        # إذا كان هذا آخر ملف، احذف النشاط أيضاً
        remaining_media = ActivityMedia.query.filter_by(activity_id=activity_id).count()
        if remaining_media == 0:
            activity = SchoolActivity.query.get(activity_id)
            if activity:
                db.session.delete(activity)
                db.session.commit()
                return jsonify({'success': True, 'message': 'تم حذف الوسائط والنشاط بنجاح', 'activity_deleted': True})
        
        return jsonify({'success': True, 'message': 'تم حذف الوسائط بنجاح'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'حدث خطأ أثناء حذف الوسائط: {str(e)}'})

@app.route('/admin/activities/<int:activity_id>/media')
def get_activity_media(activity_id):
    print(f"=== بداية get_activity_media للنشاط {activity_id} ===")
    
    if 'role' not in session or (session['role'] != 'مشرف' and session['role'] != 'مشرف محتوى'):
        print("خطأ في الصلاحيات")
        return jsonify({'success': False, 'message': 'غير مصرح لك بهذه العملية'})
    
    try:
        activity = SchoolActivity.query.get_or_404(activity_id)
        print(f"النشاط موجود: {activity.name}")
        
        media_list = ActivityMedia.query.filter_by(activity_id=activity_id).order_by(ActivityMedia.display_order).all()
        print(f"عدد الوسائط: {len(media_list)}")
        
        media_data = []
        for media in media_list:
            media_item = {
                'id': media.id,
                'media_type': media.media_type,
                'file_path': media.file_path,
                'file_name': media.file_name,
                'thumbnail_path': media.thumbnail_path,
                'is_primary': media.is_primary,
                'display_order': media.display_order,
                'upload_date': media.upload_date.isoformat() if media.upload_date else None
            }
            media_data.append(media_item)
            print(f"وسائط {media.id}: {media.file_name}, رئيسية: {media.is_primary}")
        
        print("البيانات المرسلة:", media_data)
        
        return jsonify({
            'success': True,
            'media': media_data
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'حدث خطأ: {str(e)}'})

@app.route('/activities/<int:activity_id>/media')
def get_activity_media_public(activity_id):
    """جلب وسائط النشاط للزوار"""
    try:
        activity = SchoolActivity.query.get_or_404(activity_id)
        media_list = ActivityMedia.query.filter_by(activity_id=activity_id).order_by(ActivityMedia.display_order).all()
        
        media_data = []
        for media in media_list:
            media_data.append({
                'id': media.id,
                'media_type': media.media_type,
                'file_path': media.file_path,
                'file_name': media.file_name,
                'thumbnail_path': media.thumbnail_path,
                'is_primary': media.is_primary,
                'display_order': media.display_order,
                'upload_date': media.upload_date.isoformat() if media.upload_date else None
            })
        
        return jsonify({
            'success': True,
            'media': media_data
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'حدث خطأ: {str(e)}'})



# إنشاء قاعدة البيانات إذا لم تكن موجودة
with app.app_context():
    db.create_all()
    
    # التحقق من وجود الأعمدة القديمة وحذفها إذا كانت موجودة
    try:
        inspector = db.inspect(db.engine)
        if 'school_activity' in inspector.get_table_names():
            columns = [col['name'] for col in inspector.get_columns('school_activity')]
            
            # حذف الأعمدة القديمة إذا كانت موجودة
            if 'media_type' in columns:
                db.session.execute(text("ALTER TABLE school_activity DROP COLUMN media_type"))
            if 'file_path' in columns:
                db.session.execute(text("ALTER TABLE school_activity DROP COLUMN file_path"))
            if 'file_name' in columns:
                db.session.execute(text("ALTER TABLE school_activity DROP COLUMN file_name"))
            if 'thumbnail_path' in columns:
                db.session.execute(text("ALTER TABLE school_activity DROP COLUMN thumbnail_path"))
            
            db.session.commit()
            print("تم حذف الأعمدة القديمة من جدول school_activity")
    except Exception as e:
        print(f"خطأ في فحص قاعدة البيانات: {e}")
        db.session.rollback()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

