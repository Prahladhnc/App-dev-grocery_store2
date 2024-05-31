import sqlite3
import os
import csv
from flask import Flask, send_file, make_response
from flask import render_template, url_for, redirect, abort
from flask import request, jsonify
from jinja2 import Template
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine, Table, Column, Integer, String, MetaData, bindparam, desc, or_, LargeBinary, func
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.exc import IntegrityError
from sqlalchemy.types import Date
from datetime import date, datetime
import base64
from sqlalchemy.ext.declarative import declarative_base
from io import BytesIO, StringIO
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin, login_required, roles_required
from flask_security.forms import RegisterForm 
from flask_security.utils import hash_password
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
from datetime import datetime, timedelta
from celery import Celery
from celery.schedules import crontab
import schedule 
import time
import redis
from flask_mail import Mail, Message
import pytz
import gevent
from sqlalchemy.sql import select
from sqlalchemy.sql import exists
from dateutil.parser import parse





current_dir=os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
engine = create_engine('sqlite:///groceries.sqlite3')
app.config['SECURITY_REGISTERABLE'] = True
app.config['SECURITY_SEND_REGISTER_EMAIL'] = False
app.config['SECRET_KEY'] = 'MAD2'
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///"+ os.path.join(current_dir, "groceries.sqlite3")
app.config['SECURITY_PASSWORD_HASH'] = 'sha256_crypt'
app.config['SECURITY_PASSWORD_SALT'] = 'Mad2randomsalt'
app.config['broker_url'] = 'redis://localhost:6379/0'
app.config['result_backend'] = 'redis://localhost:6379/0'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
#app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'chdalharp@gmail.com'
app.config['MAIL_PASSWORD'] = 'nook spnt fwna sysk'
app.config['MAIL_DEFAULT_SENDER'] = 'chdalharp@gmail.com'
app.config['timezone'] = 'Asia/Kolkata'  
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


app.config['CELERY_BROKER_URL'] = 'redis://localhost:6379/0'
app.config['CELERY_RESULT_BACKEND'] = 'redis://localhost:6379/0'
celery = Celery(app.name, broker=app.config['CELERY_BROKER_URL'])
celery.conf.update(app.config)


db = SQLAlchemy()
db.init_app(app)
app.app_context().push()
mail=Mail(app)


class MgrRegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')



class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

class Manager(db.Model, UserMixin):
    __tablename__='manager'
    manager_id=db.Column(db.String, primary_key=True)
    managerpass=db.Column(db.String, nullable=False)
    managername=db.Column(db.String, nullable=False)
    manageremail=db.Column(db.String, unique=True, nullable=False)
    roles = db.relationship('Role', secondary='roles_managers', backref=db.backref('managers', lazy='dynamic'))
    active = db.Column(db.Boolean())


class Admin(db.Model, UserMixin):
    __tablename__ = 'admin'
    id = db.Column(db.Integer(), primary_key=True)
    admin_id = db.Column(db.String, unique=True, nullable=False)
    adminpass = db.Column(db.String, nullable=False)
    admin_name = db.Column(db.String, nullable=False)
    admin_email = db.Column(db.String, unique=True, nullable=False)
    roles = db.relationship('Role', secondary='roles_admins', backref=db.backref('admins', lazy='dynamic'))

    
class User(db.Model, UserMixin):
    __tablename__='user'
    user_id=db.Column(db.String, primary_key=True)
    userpass=db.Column(db.String, nullable=False)
    user_name=db.Column(db.String, nullable=False)
    wallet=db.Column(db.Integer)
    roles = db.relationship('Role', secondary='roles_users', backref=db.backref('users', lazy='dynamic'))
    email = db.Column(db.String, unique=True, nullable=False, index=True)
    active = db.Column(db.Boolean())

    
roles_admins = db.Table('roles_admins',
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id')),
    db.Column('admin_id', db.Integer(), db.ForeignKey('admin.id'))
)

roles_managers = db.Table('roles_managers',
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id')),
    db.Column('manager_id', db.String, db.ForeignKey('manager.manager_id'))
)


roles_users = db.Table('roles_users',
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id')),
    db.Column('user_id', db.Integer(), db.ForeignKey('user.user_id'))
)

user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore, register_form=RegisterForm)

with app.app_context():
    db.create_all()
    admin_role = user_datastore.find_or_create_role('admin')

    admin_user = user_datastore.get_user('22f2001304@ds.study.iitm.ac.in')
    if not admin_user:
        admin_user = user_datastore.create_user(
            user_id='prahladh',
            userpass=hash_password('pra123'),  
            user_name='Prahladh',
            email='22f2001304@ds.study.iitm.ac.in',
            wallet=0,
            roles=[admin_role]
        )

        admin_record = Admin(
            admin_id='prahladh',
            adminpass=hash_password('pra123'), 
            admin_name='Prahladh',
            admin_email='22f2001304@ds.study.iitm.ac.in',
            roles=[admin_role]
        )
        db.session.add(admin_record)

        db.session.commit()

class Category(db.Model):
    __tablename__='category'
    cid=db.Column(db.Integer, primary_key=True, autoincrement=True)
    cname=db.Column(db.String, nullable=False)
    status = db.Column(db.String(20), default='Pending')

class Product(db.Model):
    __tablename__='product'
    pid=db.Column(db.Integer, primary_key=True, autoincrement=True)
    pname=db.Column(db.String, nullable=False)
    manu=db.Column(db.String, nullable=False)
    cid=db.Column(db.Integer, db.ForeignKey("category.cid"), nullable=False)
    cname=db.Column(db.String, nullable=False)
    rate=db.Column(db.String)
    added=db.Column(db.Date, nullable=False)
    quantity=db.Column(db.Integer)
    exp=db.Column(db.Date)
    pimg = db.Column(db.LargeBinary)
    unit=db.Column(db.String)
    status = db.Column(db.String(20), default='Pending')

    
class Cart(db.Model):
    __tablename__='cart'
    cartnum=db.Column(db.Integer, primary_key=True, autoincrement=True)
    pid=db.Column(db.Integer, db.ForeignKey("product.pid"), nullable=False)
    user_id=db.Column(db.String, db.ForeignKey("user.user_id"), nullable=False)
    quantity=db.Column(db.Integer, nullable=False)
    product = db.relationship('Product', backref='cart', foreign_keys=[pid])
    dt=db.Column(db.DateTime)


'''class Purchases(db.Model):
    __tablename__='purchases'
    pid=db.Column(db.Integer, db.ForeignKey("product.pid"), nullable=False)
    user_id=db.Column(db.String, db.ForeignKey("user.user_id"), nullable=False)
    quantity=db.Column(db.Integer, nullable=False)
    cost=db.Column(db.Numeric, nullable=False)
    puron=db.Column(db.DateTime, nullable=False)
    '''


 
@app.route("/", methods=['GET'])
def home():
    if request.method=='GET':
        return render_template("home.html")
    
@app.route("/adminlogin", methods=["POST", "GET"])
def adminlogin():
    if request.method=="GET":
        return render_template("adminlogin.html")
    if request.method=="POST":
        engine=create_engine('sqlite:///groceries.sqlite3', echo=True)
        Session = sessionmaker(bind=engine)
        session = Session()
        metadata = MetaData()
        admins=Table('admin', metadata,
                    Column('admin_id', String, primary_key=True),
                    Column('adminpass',String),
                    Column('adminname',String),
                    Column('adminemail',String),
        )
        admin_id=request.form["admin_id"]
        adminpass=request.form["adminpass"]
        admin=Admin.query.filter_by(admin_id=admin_id).first()
        if not admin:
            return render_template("wrongadmin.html")
        else:
            pwd=admin.adminpass
            if pwd!=adminpass:
                return render_template("wra2p.html")
            else:
                return redirect(url_for('admin_home', admin_id=admin_id))

@app.route("/managerlogin", methods=["POST", "GET"])
def managerlogin():
    if request.method=="GET":
        return render_template("managerlogin.html")
    if request.method=="POST":
        engine=create_engine('sqlite:///groceries.sqlite3', echo=True)
        Session = sessionmaker(bind=engine)
        session = Session()
        metadata = MetaData()
        managers=Table('manager', metadata,
                    Column('manager_id', String, primary_key=True),
                    Column('managerpass',String),
                    Column('managername',String),
                    Column('manageremail',String),
        )
        manager_id=request.form["manager_id"]
        managerpass=request.form["managerpass"]
        manager=Manager.query.filter_by(manager_id=manager_id).first()
        if not manager:
            return render_template("wrongmanager.html")
        else:
            pwd=manager.managerpass
            if pwd!=managerpass:
                return render_template("wrap.html")
            else:
                return redirect(url_for('manager_home', manager_id=manager_id))
            
@app.route('/signup/<role>', methods=['GET', 'POST'])
def signup(role):
    if role not in ['manager', 'user']:
        return 'Invalid role'

    if role == 'manager':
        form = MgrRegisterForm()
        user_data = {
            'manager_id': form.data['email'],
            'managerpass': form.data['password'],
            'managername': form.data['username'],
            'manageremail': form.data['email']
        }
        user_class = Manager
    else:
        form = RegisterForm()
        user_data = {
            'user_id': form.data['email'],
            'userpass': form.data['password'],
            'user_name': form.data['username'],
            'email': form.data['email'],
            'wallet': 0
        }
        user_class = User
        
    if form.validate_on_submit():
        new_user = user_class(**user_data)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('signup.html', form=form, role=role)

@app.route("/managerhome/<manager_id>", methods=["GET","POST"])
def manager_home(manager_id):
    if request.method=="GET":
        categories=Category.query.filter_by(status='Approved').all()
        products=Product.query.filter_by(status='Approved').all()
        for product in products:
            if product.pimg is not None:
                product.pimg = base64.b64encode(product.pimg).decode('utf-8')
        return render_template("managerhome.html", manager_id=manager_id, products=products, categories=categories)

@app.route("/adminhome/<admin_id>", methods=["GET","POST"])
def admin_home(admin_id):
    c=Category.query.filter_by(status='Pending').all()
    p=Product.query.filter_by(status='Pending').all()
    n1=len(c)
    n2=len(p)
    if request.method=="GET":
        categories=Category.query.filter_by(status='Approved').all()
        products=Product.query.filter_by(status='Approved').all()
        for product in products:
            if product.pimg is not None:
                product.pimg = base64.b64encode(product.pimg).decode('utf-8')
        return render_template("adminhome.html", admin_id=admin_id, products=products, categories=categories,n1=n1, n2=n2)

@app.route("/addcategory/<admin_id>", methods=["GET","POST"])
def addcategory(admin_id):
    if request.method=="GET":
        return render_template("addcategory.html", admin_id=admin_id)
    if request.method=="POST":
        engine = create_engine('sqlite:///groceries.sqlite3', echo=True)
        Session = sessionmaker(bind=engine)
        session = Session()
        metadata = MetaData()
        category = Table('category', metadata,
            Column('cid', Integer, primary_key=True),
            Column('cname', String),
            Column('status', String)
        )
        cname=request.form["cname"]
        new=category.insert().values(
            cname=cname,
            status='Approved'
        )
        session.execute(new)
        session.commit()
        return redirect(url_for('admin_home', admin_id=admin_id))


@app.route("/managerhome/<manager_id>/addcategory", methods=["GET","POST"])
def addcategoryperm(manager_id):
    if request.method=="GET":
        return render_template("addcatm.html", manager_id=manager_id)
    
    if request.method=="POST":
        engine = create_engine('sqlite:///groceries.sqlite3', echo=True)
        Session = sessionmaker(bind=engine)
        session = Session()
        metadata = MetaData()
        category = Table('category', metadata,
            Column('cid', Integer, primary_key=True),
            Column('cname', String),
            Column('status', String)
        )
        cname=request.form["cname"]
        new=category.insert().values(
            cname=cname,
            status='Pending'
        )
        session.execute(new)
        session.commit()
        return redirect(url_for('manager_home', manager_id=manager_id))
    
@app.route("/adminhome/<admin_id>/updatecat/<cid>", methods=["GET","POST"])
def updatecat(cid,admin_id):
    category=Category.query.filter_by(cid=cid).first()
    if request.method=="GET":
        return render_template("updatecat.html", category=category, admin_id=admin_id)
    elif request.method=="POST":
        cat=category
        engine = create_engine('sqlite:///groceries.sqlite3', echo=True)
        Session = sessionmaker(bind=engine)
        session = Session()
        metadata = MetaData()
        category = Table('category', metadata,
            Column('cid', Integer, primary_key=True),
            Column('cname', String)
        )
        cname=request.form["cname"]
        cat.cname=cname
        db.session.commit()
        return redirect(url_for('admin_home', admin_id=admin_id))

@app.route("/managerhome/<manager_id>/updatecat/<cid>", methods=["GET","POST"])
def updatecatperm(cid,manager_id):
    category=Category.query.filter_by(cid=cid).first()
    if request.method=="GET":
        return render_template("updatecatm.html", category=category, manager_id=manager_id)
    elif request.method=="POST":
        cat=category
        engine = create_engine('sqlite:///groceries.sqlite3', echo=True)
        Session = sessionmaker(bind=engine)
        session = Session()
        metadata = MetaData()
        category = Table('category', metadata,
            Column('cid', Integer, primary_key=True),
            Column('cname', String)
        )
        cname=request.form["cname"]
        cat.cname=cname
        db.session.commit()
        return redirect(url_for('manager_home', manager_id=manager_id))

@app.route("/adminhome/<admin_id>/deletecat/<cid>", methods=["GET","POST"])
def deletecat(cid,admin_id):
    admin=Admin.query.filter_by(admin_id=admin_id).first()
    if request.method=="GET":
        return render_template("deletecat.html", cid=cid, admin_id=admin_id)
    if request.method=="POST":
        adminpass=request.form["adminpass"]
        pwd=admin.adminpass
        if pwd!=adminpass:
            return render_template("wrdp2a.html", admin_id=admin_id, cid=cid)
        else:
            products=Product.query.filter_by(cid=cid).all()
            for product in products:
                db.session.delete(product)
            db.session.commit()
            category=Category.query.filter_by(cid=cid).first()
            db.session.delete(category)
            db.session.commit()
            return redirect(url_for('admin_home', admin_id=admin_id))

@app.route("/managerhome/<manager_id>/deletecat/<cid>", methods=["GET","POST"])
def deletecatperm(cid,manager_id):
    manager=Manager.query.filter_by(manager_id=manager_id).first()
    if request.method=="GET":
        return render_template("deletecatm.html", cid=cid, manager_id=manager_id)
    if request.method=="POST":
        managerpass=request.form["managerpass"]
        pwd=manager.managerpass
        if pwd!=managerpass:
            return render_template("wrdp2.html", manager_id=manager_id, cid=cid)
        else:
            products=Product.query.filter_by(cid=cid).all()
            for product in products:
                db.session.delete(product)
            db.session.commit()
            category=Category.query.filter_by(cid=cid).first()
            db.session.delete(category)
            db.session.commit()
            return redirect(url_for('manager_home', manager_id=manager_id))

@app.route("/adminhome/<admin_id>/addproduct", methods=["GET","POST"])
def addproduct(admin_id):
    if request.method=="GET":
        categories=Category.query.all()
        return render_template("addproduct.html", admin_id=admin_id,categories=categories)
    elif request.method=="POST":
        engine = create_engine('sqlite:///groceries.sqlite3', echo=True)
        Session = sessionmaker(bind=engine)
        session = Session()
        metadata = MetaData()
        product = Table('product', metadata,
            Column('pid', Integer, primary_key=True),
            Column('pname', String),
            Column('manu', String),
            Column('cid', Integer),
            Column('cname', String),
            Column('rate', String),
            Column('added', Date),
            Column('quantity', Integer),
            Column('exp', Date),
            Column('pimg', LargeBinary),
            Column('unit', String),
            Column('status', String)
        )
        
        pname=request.form["pname"]
        manu=request.form["manu"]
        cid=request.form["cid"]
        category=Category.query.filter_by(cid=cid).first()
        cname=category.cname
        rate=request.form["rate"]
        added= date.fromisoformat(request.form['added'])
        quantity=request.form["quantity"]
        exp=date.fromisoformat(request.form['exp'])
        uploaded_image = request.files['pimg']
        pimg_data = BytesIO(uploaded_image.read())
        unit=request.form['unit']
        status='Approved'
        new=product.insert().values(
            pname=pname,
            manu=manu,
            cid=cid,
            cname=cname,
            rate=rate,
            added=added,
            quantity=quantity,
            exp=exp,
            pimg=pimg_data.read(),
            unit=unit,
            status=status
        )
        session.execute(new)
        session.commit()
        return redirect(url_for('admin_home', admin_id=admin_id))
        
@app.route("/managerhome/<manager_id>/addproduct", methods=["GET","POST"])
def addproductperm(manager_id):
    if request.method=="GET":
        categories=Category.query.all()
        return render_template("addprom.html", manager_id=manager_id,categories=categories)
    elif request.method=="POST":
        engine = create_engine('sqlite:///groceries.sqlite3', echo=True)
        Session = sessionmaker(bind=engine)
        session = Session()
        metadata = MetaData()
        product = Table('product', metadata,
            Column('pid', Integer, primary_key=True),
            Column('pname', String),
            Column('manu', String),
            Column('cid', Integer),
            Column('cname', String),
            Column('rate', String),
            Column('added', Date),
            Column('quantity', Integer),
            Column('exp', Date),
            Column('pimg', LargeBinary),
            Column('unit', String),
            Column('status', String)
        )
        
        pname=request.form["pname"]
        manu=request.form["manu"]
        cid=request.form["cid"]
        category=Category.query.filter_by(cid=cid).first()
        cname=category.cname
        rate=request.form["rate"]
        added= date.fromisoformat(request.form['added'])
        quantity=request.form["quantity"]
        exp=date.fromisoformat(request.form['exp'])
        uploaded_image = request.files['pimg']
        pimg_data = BytesIO(uploaded_image.read())
        unit=request.form['unit']
        new=product.insert().values(
            pname=pname,
            manu=manu,
            cid=cid,
            cname=cname,
            rate=rate,
            added=added,
            quantity=quantity,
            exp=exp,
            pimg=pimg_data.read(),
            unit=unit,
            status='Pending'
        )
        session.execute(new)
        session.commit()
        return redirect(url_for('manager_home', manager_id=manager_id))

@app.route("/adminhome/<admin_id>/updatepro/<pid>", methods=["GET","POST"])
def updatepro(pid, admin_id):
    product=Product.query.filter_by(pid=pid).first()
    
    categories=Category.query.all()
    if request.method=="GET":
        return render_template("updatepro.html", product=product, admin_id=admin_id, categories=categories)    
    elif request.method=="POST":
        pro=product
        uploaded_image = request.files['pimg']
        engine = create_engine('sqlite:///groceries.sqlite3', echo=True)
        Session = sessionmaker(bind=engine)
        session = Session()
        metadata = MetaData()
        product = Table('product', metadata,
            Column('pid', Integer, primary_key=True),
            Column('pname', String),
            Column('manu', String),
            Column('cid', Integer),
            Column('cname', String),
            Column('rate', String),
            Column('added', Date),
            Column('quantity', Integer),
            Column('exp', Date),
            Column('pimg', LargeBinary),
            Column('unit', String)
        )
        pname=request.form["pname"]
        manu=request.form["manu"]
        cid=request.form["cid"]
        category=Category.query.filter_by(cid=cid).first()
        cname=category.cname
        rate=request.form["rate"]
        added=date.fromisoformat(request.form['added'])        
        quantity=request.form["quantity"]
        exp=date.fromisoformat(request.form['exp'])
        unit=request.form['unit']
        if uploaded_image:  
            pimg_data = BytesIO(uploaded_image.read())
            pro.pimg = pimg_data.read() 
        
        pro.pname=pname
        pro.manu=manu
        pro.cid=cid
        pro.cname=cname
        pro.rate=rate
        pro.added=added
        pro.quantity=quantity
        pro.exp=exp
        pro.unit=unit
        db.session.commit()
        return redirect(url_for('admin_home', admin_id=admin_id))

@app.route("/managerhome/<manager_id>/updatepro/<pid>", methods=["GET","POST"])
def updateproperm(pid, manager_id):
    product=Product.query.filter_by(pid=pid).first()
    
    categories=Category.query.all()
    if request.method=="GET":
        return render_template("updateprom.html", product=product, manager_id=manager_id, categories=categories)    
    elif request.method=="POST":
        pro=product
        uploaded_image = request.files['pimg']
        engine = create_engine('sqlite:///groceries.sqlite3', echo=True)
        Session = sessionmaker(bind=engine)
        session = Session()
        metadata = MetaData()
        product = Table('product', metadata,
            Column('pid', Integer, primary_key=True),
            Column('pname', String),
            Column('manu', String),
            Column('cid', Integer),
            Column('cname', String),
            Column('rate', String),
            Column('added', Date),
            Column('quantity', Integer),
            Column('exp', Date),
            Column('pimg', LargeBinary),
            Column('unit', String)
        )
        pname=request.form["pname"]
        manu=request.form["manu"]
        cid=request.form["cid"]
        category=Category.query.filter_by(cid=cid).first()
        cname=category.cname
        rate=request.form["rate"]
        added=date.fromisoformat(request.form['added'])        
        quantity=request.form["quantity"]
        exp=date.fromisoformat(request.form['exp'])
        unit=request.form['unit']
        if uploaded_image:  
            pimg_data = BytesIO(uploaded_image.read())
            pro.pimg = pimg_data.read() 
        
        pro.pname=pname
        pro.manu=manu
        pro.cid=cid
        pro.cname=cname
        pro.rate=rate
        pro.added=added
        pro.quantity=quantity
        pro.exp=exp
        pro.unit=unit
        db.session.commit()
        return redirect(url_for('manager_home', manager_id=manager_id))

@app.route("/adminhome/<admin_id>/pendingpro", methods=["GET","POST"])
def approvepro(admin_id):
    products=Product.query.filter_by(status='Pending').all()
    if request.method=='GET':
        return render_template("approvepro.html", products=products, admin_id=admin_id)
    if request.method=="POST":
        for product in Product.query.filter_by(status='Pending').all():
            approval_status = request.form.get(f'approval_{product.pid}')
            if approval_status == 'approve':
                product.status = 'Approved'
            elif approval_status == 'reject':
                product.status = 'Rejected'

        db.session.commit()
    return redirect(url_for('admin_home', admin_id=admin_id))

@app.route("/adminhome/<admin_id>/pendingcat", methods=["GET","POST"])
def approvecat(admin_id):
    categories=Category.query.filter_by(status='Pending').all()
    if request.method=='GET':
        return render_template("approvecat.html", categories=categories, admin_id=admin_id)
    if request.method=="POST":
        for category in Category.query.filter_by(status='Pending').all():
            approval_status = request.form.get(f'approval_{category.cid}')
            if approval_status == 'approve':
                category.status = 'Approved'
            elif approval_status == 'reject':
                category.status = 'Rejected'

        db.session.commit()
    return redirect(url_for('admin_home', admin_id=admin_id))

@app.route("/adminhome/<admin_id>/deletepro/<pid>", methods=["GET","POST"])
def deletepro(pid, admin_id):
    admin=Admin.query.filter_by(admin_id=admin_id).first()
    if request.method=="GET":
        return render_template("deletepro.html", pid=pid, admin_id=admin_id)
    if request.method=="POST":
        adminpass=request.form["adminpass"]
        pwd=admin.adminpass
        if pwd!=adminpass:
            return render_template("wrdpa.html", admin_id=admin_id, pid=pid)
        else:
            product=Product.query.filter_by(pid=pid).first()
            carts=Cart.query.filter_by(pid=pid).all()
            db.session.delete(product)
            for cart in carts:
                db.session.delete(cart)
            db.session.commit()
            return redirect(url_for('admin_home', admin_id=admin_id))

@app.route("/managerhome/<manager_id>/deletepro/<pid>", methods=["GET","POST"])
def deleteproperm(pid, manager_id):
    manager=Manager.query.filter_by(manager_id=manager_id).first()
    if request.method=="GET":
        return render_template("deleteprom.html", pid=pid, manager_id=manager_id)
    if request.method=="POST":
        managerpass=request.form["managerpass"]
        pwd=manager.managerpass
        if pwd!=managerpass:
            return render_template("wrdp.html", manager_id=manager_id, pid=pid)
        else:
            product=Product.query.filter_by(pid=pid).first()
            carts=Cart.query.filter_by(pid=pid).all()
            db.session.delete(product)
            for cart in carts:
                db.session.delete(cart)
            db.session.commit()
            return redirect(url_for('manager_home', manager_id=manager_id))


@app.route("/usersignup", methods=["GET", "POST"])
def usersignup():
    if request.method=="GET":
        return render_template("usersignup.html")
    if request.method=="POST":
        engine=create_engine('sqlite:///groceries.sqlite3', echo=True)
        Session = sessionmaker(bind=engine)
        session = Session()
        metadata = MetaData()
        users=Table('user', metadata,
                    Column('user_id', String, primary_key=True),
                    Column('userpass',String),
                    Column('user_name',String),
                    Column('email',String),
                    Column('wallet', Integer)
                    
        )
        user_id=request.form["user_id"]
        userpass=request.form["userpass"]
        user_name=request.form["user_name"]
        email=request.form["email"]
        wallet=0
        
        user=User.query.filter(or_(User.user_id == user_id, User.email == email)).all()
        if not user:
            newuser=users.insert().values(
                user_id=user_id,
                userpass=userpass,
                user_name=user_name,
                email=email,
                wallet=wallet
            )
            session.execute(newuser)
            session.commit()
            return redirect(url_for('user_home', user_id=user_id))
            
        else:
            return render_template("userexists.html")
        
@app.route("/userlogin", methods=["POST", "GET"])
def userlogin():
    if request.method=="GET":
        return render_template("userlogin.html")
    if request.method=="POST":
        engine=create_engine('sqlite:///groceries.sqlite3', echo=True)
        Session = sessionmaker(bind=engine)
        session = Session()
        metadata = MetaData()
        users=Table('user', metadata,
                    Column('user_id', String, primary_key=True),
                    Column('userpass',String),
                    Column('user_name',String),
                    Column('email',String),
                    Column('wallet', Integer)
        )
        user_id=request.form["user_id"]
        userpass=request.form["userpass"]
        user=User.query.filter_by(user_id=user_id).first()
        if not user:
            return render_template("wronguser.html")
        else:
            pwd=user.userpass
            if pwd!=userpass:
                return render_template("wrup.html")
            else:
                return redirect(url_for('user_home', user_id=user_id))



'''@app.route('/userhome/<user_id>/sort/<sort_by>', methods=['GET', 'POST'])
def user_home_sort(user_id, sort_by):
    products = Product.query.order_by(getattr(Product, sort_by)).all()
    return render_template('userhome.html', user_id=user_id, products=products)'''

@app.route('/userhome/<user_id>/search', methods=['GET'])
def user_home_search(user_id):
    search_query = request.args.get('search_query')
    products = Product.query.filter(Product.pname.ilike(f'%{search_query}%')).filter_by(status='Approved').all()
    for product in products:
            if product.pimg is not None:
                product.pimg = base64.b64encode(product.pimg).decode('utf-8')
    return render_template('userhome.html', user_id=user_id, products=products)

@app.route('/userhome/<user_id>/sort_filter', methods=['GET'])
def user_home_sort_filter(user_id):
    sort_by = request.args.get('sort_attribute')
    category = request.args.get('category')
    categories = db.session.query(Product.cname).distinct().all()

    if category == 'all':
        products = Product.query.order_by(getattr(Product, sort_by)).filter_by(status='Approved').all()
        for product in products:
            if product.pimg is not None:
                product.pimg = base64.b64encode(product.pimg).decode('utf-8')
    else:
        products = Product.query.filter_by(cname=category, status='Approved').order_by(getattr(Product, sort_by)).all()
        for product in products:
            if product.pimg is not None:
                product.pimg = base64.b64encode(product.pimg).decode('utf-8')
    return render_template('userhome.html', user_id=user_id, products=products, categories=categories)

@app.route('/api/userhome/<user_id>/products')
def get_user_products(user_id):
    products = Product.query.filter_by(status='Approved').all()
    serialized_products = [
        {
            'pid': product.pid,
            'pname': product.pname,
            'manu': product.manu,
            'cid': product.cid,
            'cname': product.cname,
            'unit': product.unit,
            'rate': product.rate,
            'added': product.added,
            'exp': product.exp,
            'quantity': product.quantity,
            'pimg': base64.b64encode(product.pimg).decode('utf-8') if product.pimg else None,
        }
        for product in products
    ]
    return jsonify(serialized_products)

@app.route("/userhome/<user_id>", methods=["GET"])
def user_home(user_id):
    if request.method=="GET":
        categories = db.session.query(Product.cname).distinct().all()
        products=Product.query.order_by(desc(Product.added)).filter_by(status='Approved').all()
        for product in products:
            if product.pimg is not None:
                product.pimg = base64.b64encode(product.pimg).decode('utf-8')
        return render_template("userhome.html", user_id=user_id, products=products, categories=categories)

@app.route("/userhome/<user_id>/cart/<pid>", methods=["GET", "POST"])
def addtocart(user_id, pid):
    if request.method=="GET":
        product=Product.query.filter_by(pid=pid).first()
        product_data = {
        'pid': product.pid,
        'pname': product.pname,
        'rate': product.rate,
        'cname': product.cname,
        'added': product.added,
        'exp': product.exp,
        'quantity': product.quantity 
    }
        if product.quantity==0:
            return render_template("nostock.html", user_id=user_id, pid=pid)
        else:
            return render_template("addtocart.html", user_id=user_id, pid=pid, product=product_data, rate=product.rate)
    if request.method=="POST":
        engine = create_engine('sqlite:///groceries.sqlite3', echo=True)
        Session = sessionmaker(bind=engine)
        session = Session()
        metadata = MetaData()
        carts = Table('cart', metadata,
            Column('cartnum', Integer, primary_key=True),
            Column('pid', Integer),
            Column('user_id', String),
            Column('quantity', Integer),
            Column('dt', String)
        )
        quantity=int(request.form["quantity"])
        
        new=carts.insert().values(
            pid=pid,
            user_id=user_id,
            quantity=quantity,
            dt=datetime.now()
        )
        session.execute(new)
        session.commit()
        product=Product.query.filter_by(pid=pid).first()
        product.quantity=product.quantity-quantity
        db.session.commit()
        return redirect(url_for('user_home', user_id=user_id))

    
    
@app.route("/userhome/<user_id>/gotocart", methods=["GET", "POST"])
def gotocart(user_id):
    if request.method=="GET":
        cart_items=Cart.query.filter_by(user_id=user_id).all()
        cost=0
        cart_details = []
        for item in cart_items:
            product = item.product
            pimg_data = product.pimg
            if pimg_data is not None:
                pimg_base64 = base64.b64encode(pimg_data).decode('utf-8')
            else:
                pimg_base64 = None
            cart_details.append({
                'cartnum': item.cartnum,
                'user_id': item.user_id,
                'pid': item.pid,
                'quantity': item.quantity,
                'pname': product.pname,
                'cname': product.cname,
                'manu': product.manu,
                'rate': product.rate,
                'added': product.added,
                'exp': product.exp,
                'pimg':product.pimg,
                'product_quantity': product.quantity,
                'pimg': pimg_base64,
                'unit': product.unit
            })
        
            
        for product in cart_details:
            x=int(product['rate'])*int(product['quantity'])
            cost=cost+x
        user=User.query.filter_by(user_id=user_id).first()
        wallet=user.wallet
        return render_template("gotocart.html", user_id=user_id, cart_details=cart_details, cost=cost, wallet=wallet)
    
@app.route('/userhome/<user_id>/gotocart/change/<cartnum>', methods=["GET", "POST"])
def updatecart(user_id, cartnum):
    odr=Cart.query.filter_by(cartnum=cartnum).first()
    prod=odr.product
    if request.method=="GET":
        pname=prod.pname
        left=prod.quantity+odr.quantity
        return render_template("updatecart.html", user_id=user_id, odr=odr, pname=pname, cartnum=cartnum, left=left)
    
    if request.method=="POST":
        change=int(request.form['quantity'])
        prod.quantity=prod.quantity+odr.quantity-change
        odr.quantity=change
        db.session.commit()
        return redirect(url_for('gotocart', user_id=user_id))

@app.route("/userhome/<user_id>/gotocart/remove/<cartnum>", methods=["GET","POST"])
def removecart(user_id, cartnum):
    if request.method=="GET":
        cart=Cart.query.filter_by(cartnum=cartnum).first()
        product=cart.product
        product.quantity+=cart.quantity
        db.session.delete(cart)
        db.session.commit()
        return redirect(url_for('gotocart', user_id=user_id))
@app.route("/userhome/<user_id>/wallet", methods=["GET", "POST"])
def wallet(user_id):
    if request.method=='GET':
        user=User.query.filter_by(user_id=user_id).first()
        return render_template('wallet.html', user=user, user_id=user_id)

@app.route("/userhome/<user_id>/wallet/add", methods=["GET", "POST"])
def addmoney(user_id):
    user=User.query.filter_by(user_id=user_id).first()
    if request.method=='GET':
        return render_template('addmoney.html', user=user, user_id=user_id)
    if request.method=='POST':
        wallet=request.form['wallet']
        userpass=request.form['userpass']
        if user.userpass!=userpass:
            return render_template('wrmp.html', user=user, user_id=user_id)
        else:
            user.wallet=user.wallet + int(wallet)
            db.session.commit()
            return redirect(url_for('wallet', user_id=user_id))
        

def send_email(recipient_email):
    subject = 'Reminder: Your Cart is Empty!'
    body = 'Please visit our website Grocy Quick to add items to your cart.'
    sender_email = 'chdalharp@gmail.com'

    msg = Message(subject, sender=sender_email, recipients=[recipient_email])
    msg.body = body
    mail.send(msg)

@celery.task
def send_cart_remainder_emails():
    ist = pytz.timezone('Asia/Kolkata')
    twenty_four_hours_ago_ist = datetime.now(ist) - timedelta(hours=24)
    users_with_empty_carts = (
    db.session.query(User)
    .filter(
        ~exists().where(
            (Cart.user_id == User.user_id)
            & (Cart.dt >= twenty_four_hours_ago_ist)
        )
    ).all()
)
    l=[]
    for user in users_with_empty_carts:
        send_email(user.email)
        l.append(user.email)
    return l
        

        
def send_email2(user_id, user_carts):
    user = User.query.get(user_id)
    ovr=0
    cart_data = []
    for cart in user_carts:
        product = Product.query.get(cart.pid)
        total=int(cart.quantity) * int(product.rate)
        ovr+=total
        product = Product.query.get(cart.pid)
        cart_data.append({
            "Product": product.pname,
            "Category": product.cname,
            "Quantity": cart.quantity,
            "Rate": product.rate,
            "Total Expense": total,
            "Date": str(cart.dt)
        })
    html_table = render_template('email_table.html', cart_data=cart_data)
    subject = "Monthly Cart Summary"
    body = f"Dear {user.email},\n \n"
    body += "Here is your monthly cart summary:\n \n"
    body += html_table
    body += f"\n Total expense this month is {ovr}Rs"
    msg = Message(subject, recipients=[user.email], html=body)
    mail.send(msg)
    return ("Successful")

    
@celery.task
def send_monthly_cart_email():
    now = datetime.now()
    last_month_start = datetime(now.year, 1, 1)
    carts = (
        Cart.query
        .filter(Cart.dt >= last_month_start, Cart.dt < now)
        .all()
    )
    user_carts = {}
    for cart in carts:
        if cart.user_id not in user_carts:
            user_carts[cart.user_id] = []
        user_carts[cart.user_id].append(cart)
    for user_id, user_carts in user_carts.items():
        send_email2(user_id, user_carts)
    return ("Task Done")
    
celery.conf.beat_schedule = {
    'send-cart-remainder-emails': {
        'task': 'app.send_cart_remainder_emails',
        'schedule': crontab(hour=22, minute=44),
    },
    'send-monthly-cart-emails': {
        'task': 'app.send_monthly_cart_email',
        'schedule': crontab(hour=22, minute=44, day_of_month=24),
    },
}

@celery.task
def export_products():
    products = Product.query.all()

    filename = 'products_export.csv'

    with open(filename, 'w', newline='') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(['Product Name', 'Category', 'Remaining Quantity', 'Rate', 'Unit','Units Sold'])
        for product in products:
            engine = create_engine('sqlite:///groceries.sqlite3', echo=True)
            Session = sessionmaker(bind=engine)
            session = Session()
            metadata = MetaData()
            p=product.pid
            total_quantity = session.query(func.sum(Cart.quantity)).filter(Cart.pid == p).scalar()
            csv_writer.writerow([product.pname, product.cname, product.quantity, product.rate, product.unit, total_quantity])

    return filename

@app.route('/export_and_download')
def export_and_download():
    job = export_products.apply_async()
    job_id = job.id

    while not job.ready():
        pass

    filename = job.result

    response = make_response(send_file(filename, as_attachment=True, download_name=f'{filename}.csv',  mimetype='text/csv'))
    response.headers['Content-Disposition'] = f'attachment; filename={filename}.csv'
    
    return response


if __name__=="__main__":
    db.create_all()
    app.run()
    

