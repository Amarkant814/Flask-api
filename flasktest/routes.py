
from functools import wraps
from flask import config, json, render_template, url_for, flash, redirect, request, jsonify, make_response
from flask_limiter.extension import Limiter
from sqlalchemy.orm import session
from flasktest import app, db, bcrypt
from flasktest.models import User
from flasktest.forms import RegistrationForm, LoginForm, UpdateAccountForm
from flask_login import login_user, current_user, logout_user, login_required
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import secrets
import os
import datetime
import jwt 


limiter = Limiter(
    app, 
    key_func=get_remote_address
)




def token_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            return jsonify({ 'Alert!': 'token is missing!'})
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify({'Alert!': 'Invalid Token! '})
        return func(*args, **kwargs)
    return decorated

@app.route("/")
@app.route("/home")
def home():
    return render_template('home.html')

@app.route("/about")
@limiter.limit('5 per minute')
def about():
    return render_template('about.html', title = 'About')

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username = form.username.data, email = form.email.data, password = hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your Account has been created! You are now able to login', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title = 'Register', form = form)


@app.route("/login", methods =['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        flash('You are already logged in', 'success')
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            token = jwt.encode({'user' : form.email.data , 'exp': str(datetime.datetime.utcnow()+datetime.timedelta(minutes=30))}, app.config['SECRET_KEY'])
            return jsonify({ 'token': token.decode('UTF-8') })
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Wrong Credentials', 'danger')
    return render_template('login.html', title = 'Login', form = form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))


def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/pics', picture_fn)
    form_picture.save(picture_path)
    return picture_fn

@app.route('/account/<string:filename>')
@login_required
def displayimage(filename):
    return render_template("home.html")


@app.route("/account", methods = ['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file
        db.session.commit()
        #flash('Your picture has been updloaded', 'success')
        return redirect(url_for('account', filename=form.picture.data))
    image_file = url_for('static', filename = 'pics/' + current_user.image_file)
    return render_template('account.html', title = 'Account',image_file=image_file, form=form)


@app.route('/auth')
@token_required
def auth():
    return 'JWT token verified'