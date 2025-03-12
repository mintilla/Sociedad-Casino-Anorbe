# -*- coding: utf-8 -*-

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import bcrypt
from datetime import datetime, timedelta
import os

app = Flask(__name__)
app.secret_key = 'tu_clave_secreta'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.path.dirname(__file__), 'casino_anorbe.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Modelo de Usuario
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120))  # La contraseña puede ser NULL inicialmente
    es_socio = db.Column(db.Boolean, default=False)  # Indica si el usuario es un socio
    es_admin = db.Column(db.Boolean, default=False)  # Indica si el usuario es un administrador

    # Relación inversa con el modelo Reserva
    reservas = db.relationship('Reserva', backref='usuario', lazy=True)

# Modelo de Reserva
class Reserva(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    fecha = db.Column(db.DateTime, nullable=False)
    tipo_evento = db.Column(db.String(50), nullable=False)  # Almuerzo, Comida, Merienda, Cena
    comensales = db.Column(db.Integer, nullable=False)  # Número de comensales
    usa_horno = db.Column(db.Boolean, default=False)  # ¿Se usará el horno?
    email_notificacion = db.Column(db.String(120))  # Email para notificaciones
    fecha_creacion = db.Column(db.DateTime, default=datetime.now)  # Fecha y hora de creación de la reserva

# Modelo de Configuración
class Configuracion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    clave = db.Column(db.String(50), unique=True, nullable=False)
    valor = db.Column(db.String(120), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Crear la base de datos y cargar socios existentes
with app.app_context():
    db.create_all()
    # Crear un usuario administrador por defecto (si no existe)
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        hashed_password = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt())
        new_admin = User(username='admin', password=hashed_password.decode('utf-8'), es_admin=True)
        db.session.add(new_admin)
        db.session.commit()

    # Crear configuraciones por defecto (si no existen)
    if not Configuracion.query.filter_by(clave='aforo_maximo').first():
        db.session.add(Configuracion(clave='aforo_maximo', valor='50'))
    if not Configuracion.query.filter_by(clave='limite_hornos').first():
        db.session.add(Configuracion(clave='limite_hornos', valor='2'))
    if not Configuracion.query.filter_by(clave='max_dias_antelacion').first():
        db.session.add(Configuracion(clave='max_dias_antelacion', valor='30'))  # 30 días de antelación
    db.session.commit()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].lower()  # Convertir a minúsculas
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.password and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            login_user(user)
            flash('Inicio de sesión exitoso', 'success')
            return redirect(url_for('calendar'))
        else:
            flash('Usuario o contraseña incorrectos', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión', 'success')
    return redirect(url_for('index'))

@app.route('/elegir-contrasena', methods=['GET', 'POST'])
def elegir_contrasena():
    if request.method == 'POST':
        username = request.form['username'].lower()  # Convertir a minúsculas
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        # Verificar que el usuario existe, es socio y no tiene contraseña
        if user and user.es_socio and not user.password:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            user.password = hashed_password.decode('utf-8')
            db.session.commit()
            flash('Contraseña guardada exitosamente', 'success')
            return redirect(url_for('login'))
        else:
            flash('No eres un socio autorizado o ya has elegido una contraseña', 'error')
    
    return render_template('elegir_contrasena.html')

@app.route('/calendar')
@login_required
def calendar():
    # Obtener configuraciones desde la base de datos
    aforo_maximo = Configuracion.query.filter_by(clave='aforo_maximo').first().valor
    limite_hornos = Configuracion.query.filter_by(clave='limite_hornos').first().valor

    # Obtener reservas del mes actual
    hoy = datetime.today()
    reservas_mes = Reserva.query.filter(
        db.extract('year', Reserva.fecha) == hoy.year,
        db.extract('month', Reserva.fecha) == hoy.month
    ).all()

    # Pasar configuraciones y reservas a la plantilla
    return render_template('calendar.html', configuracion={'aforo_maximo': aforo_maximo, 'limite_hornos': limite_hornos}, reservas_mes=reservas_mes)

@app.route('/api/reservas')
@login_required
def get_reservas():
    reservas = Reserva.query.all()
    eventos = []
    for reserva in reservas:
        eventos.append({
            'title': f'{reserva.usuario.username} - {reserva.tipo_evento} ({reserva.comensales} personas)',  # Eliminamos el "0"
            'start': reserva.fecha.isoformat(),
            'description': f'Horno: {"Sí" if reserva.usa_horno else "No"}'
        })
    return jsonify(eventos)

@app.route('/api/reservas', methods=['POST'])
@login_required
def crear_reserva():
    data = request.get_json()
    try:
        fecha = datetime.fromisoformat(data['fecha'])
    except ValueError:
        return jsonify({'error': 'Formato de fecha inválido'}), 400

    tipo_evento = data.get('tipo_evento')
    comensales = data.get('comensales')
    usa_horno = data.get('usa_horno', False)
    email_notificacion = data.get('email_notificacion', '')

    # Validar número máximo de días de antelación
    max_dias_antelacion = int(Configuracion.query.filter_by(clave='max_dias_antelacion').first().valor)
    dias_antelacion = (fecha.date() - datetime.today().date()).days
    if dias_antelacion > max_dias_antelacion:
        return jsonify({'error': f'No se pueden hacer reservas con más de {max_dias_antelacion} días de antelación'}), 400

    # Validar aforo máximo por evento
    aforo_maximo = int(Configuracion.query.filter_by(clave='aforo_maximo').first().valor)
    reservas_del_evento = Reserva.query.filter(
        db.func.date(Reserva.fecha) == fecha.date(),
        Reserva.tipo_evento == tipo_evento
    ).all()
    total_comensales = sum(r.comensales for r in reservas_del_evento)
    if total_comensales + comensales > aforo_maximo:
        return jsonify({'error': f'Aforo máximo alcanzado para {tipo_evento}'}), 400

    # Validar límite de hornos
    if usa_horno:
        limite_hornos = int(Configuracion.query.filter_by(clave='limite_hornos').first().valor)
        hornos_del_dia = sum(1 for r in reservas_del_evento if r.usa_horno)
        if hornos_del_dia >= limite_hornos:
            return jsonify({'error': 'Límite de hornos alcanzado para este día'}), 400

    # Crear la reserva con la fecha y hora actual
    nueva_reserva = Reserva(
        user_id=current_user.id,
        fecha=fecha,
        tipo_evento=tipo_evento,
        comensales=comensales,
        usa_horno=usa_horno,
        email_notificacion=email_notificacion,
        fecha_creacion=datetime.now()  # Guardar la fecha y hora actual
    )
    db.session.add(nueva_reserva)
    db.session.commit()

    return jsonify({'message': 'Reserva creada exitosamente'})

@app.route('/admin')
@login_required
def admin():
    if not current_user.es_admin:
        flash('No tienes permisos de administrador', 'error')
        return redirect(url_for('index'))
    usuarios = User.query.all()
    return render_template('admin.html', usuarios=usuarios)

@app.route('/admin/agregar-usuario', methods=['POST'])
@login_required
def agregar_usuario():
    if not current_user.es_admin:
        flash('No tienes permisos de administrador', 'error')
        return redirect(url_for('index'))
    username = request.form['username'].lower()  # Convertir a minúsculas
    es_socio = 'es_socio' in request.form
    es_admin = 'es_admin' in request.form

    if User.query.filter_by(username=username).first():
        flash('El usuario ya existe', 'error')
    else:
        nuevo_usuario = User(username=username, es_socio=es_socio, es_admin=es_admin)
        db.session.add(nuevo_usuario)
        db.session.commit()
        flash('Usuario agregado exitosamente', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/borrar-usuario/<int:user_id>', methods=['POST'])
@login_required
def borrar_usuario(user_id):
    if not current_user.es_admin:
        flash('No tienes permisos de administrador', 'error')
        return redirect(url_for('index'))
    usuario = User.query.get(user_id)
    if usuario:
        db.session.delete(usuario)
        db.session.commit()
        flash('Usuario borrado exitosamente', 'success')
    else:
        flash('Usuario no encontrado', 'error')
    return redirect(url_for('admin'))

@app.route('/admin/restablecer-contrasena/<int:user_id>', methods=['POST'])
@login_required
def restablecer_contrasena_admin(user_id):
    if not current_user.es_admin:
        flash('No tienes permisos de administrador', 'error')
        return redirect(url_for('index'))

    usuario = User.query.get(user_id)
    if usuario:
        # Borrar la contraseña existente
        usuario.password = None
        db.session.commit()
        flash(f'Contraseña restablecida para {usuario.username}. El usuario debe elegir una nueva contraseña al iniciar sesión.', 'success')
    else:
        flash('Usuario no encontrado', 'error')
    return redirect(url_for('admin'))

@app.route('/admin/reservas')
@login_required
def admin_reservas():
    if not current_user.es_admin:
        flash('No tienes permisos de administrador', 'error')
        return redirect(url_for('index'))
    reservas = Reserva.query.all()
    return render_template('admin_reservas.html', reservas=reservas)

@app.route('/borrar-reserva/<int:reserva_id>', methods=['POST'])
@login_required
def borrar_reserva(reserva_id):
    reserva = Reserva.query.get(reserva_id)
    if not reserva:
        flash('Reserva no encontrada', 'error')
        return redirect(url_for('admin_reservas'))

    # Permitir que los administradores borren cualquier reserva
    # o que los socios borren solo sus propias reservas
    if current_user.es_admin or reserva.user_id == current_user.id:
        db.session.delete(reserva)
        db.session.commit()
        flash('Reserva borrada exitosamente', 'success')
    else:
        flash('No tienes permisos para borrar esta reserva', 'error')

    # Redirigir a la página de reservas del administrador o del socio
    if current_user.es_admin:
        return redirect(url_for('admin_reservas'))
    else:
        return redirect(url_for('calendar'))

@app.route('/admin/configuraciones', methods=['GET', 'POST'])
@login_required
def admin_configuraciones():
    if not current_user.es_admin:
        flash('No tienes permisos de administrador', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        aforo_maximo = request.form['aforo_maximo']
        limite_hornos = request.form['limite_hornos']
        max_dias_antelacion = request.form['max_dias_antelacion']

        # Actualizar configuraciones
        config_aforo = Configuracion.query.filter_by(clave='aforo_maximo').first()
        config_aforo.valor = aforo_maximo

        config_hornos = Configuracion.query.filter_by(clave='limite_hornos').first()
        config_hornos.valor = limite_hornos

        config_dias = Configuracion.query.filter_by(clave='max_dias_antelacion').first()
        config_dias.valor = max_dias_antelacion

        db.session.commit()
        flash('Configuraciones actualizadas exitosamente', 'success')

    # Obtener configuraciones actuales
    aforo_maximo = Configuracion.query.filter_by(clave='aforo_maximo').first().valor
    limite_hornos = Configuracion.query.filter_by(clave='limite_hornos').first().valor
    max_dias_antelacion = Configuracion.query.filter_by(clave='max_dias_antelacion').first().valor

    return render_template('admin_configuraciones.html', aforo_maximo=aforo_maximo, limite_hornos=limite_hornos, max_dias_antelacion=max_dias_antelacion)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=10000)