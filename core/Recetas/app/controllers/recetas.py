from flask import render_template, redirect, session, request, flash
from app.models.recetas import Receta
from app import app

@app.route('/recetas')
def recetas():

    if 'usuario' not in session:
        return redirect('/login')
    
    recetas = Receta.get_all()
    return render_template('recetas/inicio.html', recetas=recetas)

@app.route('/recetas/crear')
def recetas_crear():

    if 'usuario' not in session:
        return redirect('/login')
    
    session['usuario']['nombre']
    return render_template('recetas/crear.html')

@app.route('/procesar_receta', methods=['POST'])
def procesar_receta():
    print('DATOS DE LA RECETA:', request.form)

    data = {
        **request.form,
        'usuario_id': session ['usuario']['usuario_id']
    }
    receta = Receta.save(data)

    flash(f'Receta {receta.nombre} creada exitosamente', 'success')
    return redirect('/recetas')

@app.route('/recetas/<id>')
def receta_id(id):

    if 'usuario' not in session:
        return redirect('/login')
    
    receta = Receta.get(id)
    return render_template('recetas/detalle.html', receta=receta)