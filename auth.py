from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth', __name__)

# Route Login
@auth.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email = email).first()

        if user:
            if check_password_hash(user.password, password):
                flash('Logged in Succefully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect Password.', category='error')
        else:
            flash('Email does not exists.', category='error')

    return render_template('login.html', user=current_user)


# Route Sign Up
@auth.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == 'POST':

        email = request.form.get('email')
        nombre = request.form.get('nombre')
        apellido = request.form.get('apellido')
        password = request.form.get('password')
        passwordconfirm = request.form.get('passwordconfirm')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email Already exists.', category='error')
        elif len(email) <= 1:
            flash('Email incorrecto.', category='error')
        elif len(nombre) <= 1:
            flash('Nombre incorrecto.', category='error')
        elif len(apellido) <= 1:
            flash('Apellido incorrecto.', category='error')
        elif len(password) < 6:
            flash('La contraseña es menor a 6 caracteres', category='error')
        elif password != passwordconfirm:
            flash('Contraseñas no coinciden.', category='error')
        else:
            #add to Database
            new_user = User(email = email, nombre = nombre, apellido = apellido, password = generate_password_hash(password, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            flash('Cuenta creada', category='success')

            return redirect(url_for('views.home'))

    return render_template('signup.html', user=current_user)


# Route Logout
@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))