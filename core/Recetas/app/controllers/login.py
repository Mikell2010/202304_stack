from flask import render_template, request, session, flash, redirect
from app.models.usuarios import Usuario
from app import app
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)

@app.route('/login')
def login():
    if 'usuario' in session:
        return redirect('/')
    
    return render_template('auth/login.html')

@app.route('/procesar_login', methods=['POST'])
def procesar_login():
    print('POST:', request.form)

    usuario_encontrado = Usuario.get_by_email(request.form['email'])
    if not usuario_encontrado:
        flash('Existe un error en tu correo o contraseña', 'danger')
    return redirect('/login')

    login_seguro = bcrypt.check_password_hash(usuario_encontrado.password, request.form['password'])
    data = {
        'usuario_id': usuario_encontrado.id,
        'nombre': usuario_encontrado.nombre,
        'apellido': usuario_encontrado.apellido,
        'email': usuario_encontrado.email,
    }

    if login_seguro:
        session['usuario'] = data
        flash('Genial, pudiste entrar sin problemas!!!!', 'success')
    else:
        flash('Existe un error en tu correo o contraseña', 'danger')
        return redirect('/login')
    
    return redirect('/')
    

@app.route('/salir')
def salir():
    session.clear()
    flash('Saliste sin problemas!!!', 'info')
    return redirect('/login')

