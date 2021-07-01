import os

import time

from flask import Flask, render_template, redirect, url_for, flash

from flask_login import LoginManager, login_user, current_user, login_required, logout_user

from flask_socketio import SocketIO, join_room, leave_room, send

from passlib.hash import pbkdf2_sha256
from flask_sqlalchemy import SQLAlchemy
#from wtform_fields import *
from flask_login import UserMixin
##########libreias pruebassssssss################
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, EqualTo, ValidationError
from passlib.hash import pbkdf2_sha256

##########Librerias prueba##############################


dbdir = "sqlite:///" + os.path.abspath(os.getcwd()) + "/database.db"
# Configure app
app = Flask(__name__)
app.secret_key = "os.environ.get('SECRET')"

# Configure db
app.config['SQLALCHEMY_DATABASE_URI'] = dbdir
app.config["SQLAlCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


#creacion base
class User(UserMixin, db.Model):
    """User model"""
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), unique=True)
    password = db.Column(db.String(), nullable=False)


##########################PRUEBAAAAAAAAAAAAAAAAAAAAAA#


def invalid_credentials(form, field):
    """Username and password checker"""

    username_entered = form.username.data
    password_entered = field.data

    user_object = User.query.filter_by(username=username_entered).first()
    if user_object is None:
        raise ValidationError(
            "Nombre de usuario o contraseña incorrecta")
    elif not pbkdf2_sha256.verify(password_entered, user_object.password):
        raise ValidationError("Nombre de usuario o contraseña incorrecta")


class RegistrationForm(FlaskForm):
    """Registration form"""
    username = StringField('username_label',
                           validators=[InputRequired(message="Nombre de usuario requerido"),
                                       Length(min=4, max=25,
                                              message="El nombre de usuario debe tener entre 4 a 25 caracteres")])

    password = PasswordField('password_label',
                             validators=[InputRequired(message="La contraseña es requerida"),
                                         Length(min=4, max=25,
                                                message="La contraseña debe tener entre 4 a 25 caracteres")])

    confirm_pswd = PasswordField('confirm_pswd_label',
                                 validators=[InputRequired(message="La contraseña es requerida"),
                                             EqualTo('password', message="Las contraseñas deben coincidir.")])

    submit_button = SubmitField('Create')

    def validate_username(self, username):
        user_object = User.query.filter_by(username=username.data).first()
        if user_object:
            raise ValidationError(
                "Nombre de usuario existente, porfavor selecciona otro")


class LoginForm(FlaskForm):
    """Login Form"""
    username = StringField('username_label', validators=[
                           InputRequired(message="Nombre de usuario requerido")])
    password = PasswordField('password_label', validators=[
        InputRequired(message="La contraseña es requerida"), invalid_credentials])
    submit_button = SubmitField('Iniciar')


class RoomForm(FlaskForm):
    """Room form"""
    roomname = StringField('room_label', validators=[
        InputRequired(message="Campo requerido")
    ])
    submit_button = SubmitField('Create')



#########################PRUEBA##################################
# initialize socketIO
socketio = SocketIO(app)
ROOMS = ['Anime', 'Manga', 'Videojuegos', 'Musica', 'Megas', "Random","Lounge"]
USERS = []
# Configure flask login
login = LoginManager(app)
login.init_app(app)


@login.user_loader
def load_user(id):

    return User.query.get(int(id))


@app.route('/', methods=['GET', 'POST'])
def index():

    reg_form = RegistrationForm()
    # updated db if validation is succesfull
    if reg_form.validate_on_submit():
        username = reg_form.username.data
        password = reg_form.password.data

        hashed_pswd = pbkdf2_sha256.hash(password)

        # Add user to database
        user = User(username=username, password=hashed_pswd)
        db.session.add(user)
        db.session.commit()
        flash('Registro satisfactorio, por favor inicia sesion', 'success')
        return redirect(url_for('login'))

    return render_template('index.html', form=reg_form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm()
    # Allow if validation success
    if login_form.validate_on_submit():
        USERS.append(login_form.username.data)
        user_object = User.query.filter_by(
            username=login_form.username.data).first()
        login_user(user_object)
        return redirect(url_for('chat'))

    return render_template('login.html', form=login_form)


@app.route("/create", methods=["GET", "POST"])
def create():
    create_form = RoomForm()
    if create_form.validate_on_submit():
        ROOMS.append(create_form.roomname.data)
        return redirect(url_for('chat'))
    return render_template('create.html', form=create_form)


@app.route("/chat", methods=["GET", "POST"])
@login_required
def chat():
    # if not current_user.is_authenticated:
    #     flash('Porfavor inicia sesion', 'danger')
    #     return redirect(url_for('login'))

    return render_template('chat.html', username=current_user.username, rooms=ROOMS, users=USERS)


@app.route("/logout", methods=["GET"])
def logout():
    logout_user() #funcion de flask, que hace pop a la session actual
    flash("Has cerrado sesion", 'success')
    return redirect(url_for('login'))


@socketio.on('incoming-msg')
def message(data):
    print(f"\n\n{data}\n\n")
    msg = data["msg"]
    username = data["username"]
    room = data["room"]
    # Set timestamp
    time_stamp = time.strftime('%b-%d %I:%M%p', time.localtime())
    send({"username": username, "msg": msg, "time_stamp": time_stamp}, room=room)


@socketio.on('join')
def join(data):
    join_room(data['room'])
    send({'msg': data['username'] + " ha entrado a la sala" +
          data['room']}, room=data['room'])


@socketio.on('leave')
def leave(data):
    leave_room(data['room'])
    send({'msg': data['username'] + " ha dejado la sala" +
          data['room']}, room=data['room'])


if __name__ == '__main__':
    db.create_all()
    app.run()
