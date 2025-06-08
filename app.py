from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response, send_from_directory, jsonify
import bcrypt
import os
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from functools import wraps
from pymongo import MongoClient
from gridfs import GridFS
from bson.objectid import ObjectId
from bson import json_util 
import json 
import re
from dotenv import load_dotenv

# Carrega as variáveis de ambiente do arquivo .env
load_dotenv()

app = Flask(__name__, template_folder='templates')
# Usar FLASK_SECRET_KEY do .env ou gerar uma aleatória se não definida
app.secret_key = os.environ.get('FLASK_SECRET_KEY', os.urandom(24)) 
app.permanent_session_lifetime = timedelta(days=30) # Aumenta a vida útil da sessão

# --- Configurações de Pastas ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'static', 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
# As pastas 'PROFILE_PICS_FOLDER' e 'IMAGES_FOLDER' não são usadas diretamente no Chefabook
# para upload, mas as mantemos para evitar erros se houver referências estáticas.
app.config['PROFILE_PICS_FOLDER'] = os.path.join(BASE_DIR, 'static', 'profile_pics')
app.config['IMAGES_FOLDER'] = os.path.join(BASE_DIR, 'static', 'images')

# --- Conexão com MongoDB ---
# Usando a URI do Chefabook
mongo_uri = os.environ.get('MONGO_URI', 'mongodb+srv://juliocardoso:ttAJxnWdq6VteFCD@cluster0.fynj6mg.mongodb.net/chefabook?retryWrites=true&w=majority&appName=Cluster0')
client = MongoClient(mongo_uri)
db = client.get_database('chefabook') # Banco de dados do Chefabook

# --- Coleções do Banco de Dados Chefabook ---
fs = GridFS(db) # Para lidar com arquivos grandes (imagens de receitas)
usuarios_col = db['usuarios']
receitas_col = db['receitas']
feedbacks_col = db['feedbacks']

# Credenciais do Administrador (mantido do Chefabook)
ADMIN_CREDENTIALS = {
    "email": "admin@email.com",
    "password": "senha123"
}

# --- Decorators ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Por favor, faça login para acessar esta página.", "error")
            return redirect(url_for('login'))
        
        # Admin é tratado de forma diferente no consentimento
        if session.get('user_id') != "admin" and not session.get('consent_given', False):
            flash("Por favor, aceite nossos Termos de Uso para continuar.", "info")
            return redirect(url_for('login', require_consent=True))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or not session.get('user_admin'):
            flash("Acesso restrito a administradores.", "error")
            return redirect(url_for('login_admin'))
        return f(*args, **kwargs)
    return decorated_function

# --- Funções auxiliares (Validações) ---
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def validar_email(email): 
    return re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email)

def validar_telefone(telefone): 
    telefone_limpo = re.sub(r'\D', '', telefone)
    return len(telefone_limpo) >= 10 and len(telefone_limpo) <= 11

# --- Rotas Principais ---
@app.route('/')
def home():
    """
    Redireciona para a página de login.
    """
    if 'user_id' in session and session.get('consent_given', False):
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required 
def dashboard():
    if session.get('user_id') == "admin":
        return redirect(url_for('painel_admin'))
    
    user_id_str = session['user_id']
    usuario_logado = usuarios_col.find_one({'_id': ObjectId(user_id_str)})
    
    receitas_recentes = list(receitas_col.find().sort("data_cadastro", -1).limit(5))
    for r in receitas_recentes:
        r['_id'] = str(r['_id'])

    return render_template('dashboard.html',
                           user_nome=session.get('user_nome', 'Usuário'),
                           usuario_logado=usuario_logado,
                           receitas_recentes=receitas_recentes)

# --- Rotas de Autenticação ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        senha = request.form.get('senha', '').strip()

        if email == ADMIN_CREDENTIALS["email"]:
            return jsonify({
                'status': 'redirect',
                'title': 'Acesso Administrativo',
                'message': 'Por favor, utilize o login administrativo.',
                'redirect': url_for('login_admin')
            })

        if not email or not validar_email(email):
            return jsonify({
                'status': 'error',
                'title': 'E-mail Inválido',
                'message': 'Por favor, insira um e-mail válido.'
            }), 400
        
        if not senha:
            return jsonify({
                'status': 'error',
                'title': 'Senha Necessária',
                'message': 'Por favor, insira sua senha.'
            }), 400

        try:
            usuario = usuarios_col.find_one({'email': email})
            
            if not usuario:
                return jsonify({
                    'status': 'error',
                    'title': 'E-mail Não Encontrado',
                    'message': 'E-mail não encontrado. Verifique ou cadastre-se.'
                }), 401
            else:
                if bcrypt.checkpw(senha.encode('utf-8'), usuario['senha']):
                    session['user_id'] = str(usuario['_id'])
                    session['user_nome'] = usuario['nome']
                    session['user_admin'] = usuario.get('admin', False) 
                    session['consent_given'] = usuario.get('consent_given', False)

                    if not session['consent_given']:
                        return jsonify({
                            'status': 'consent_required',
                            'title': 'Termos de Uso',
                            'message': 'Por favor, aceite nossos Termos de Uso e Política de Privacidade para acessar a plataforma.',
                            'redirect': url_for('login', require_consent=True)
                        })
                    else:
                        return jsonify({
                            'status': 'success',
                            'title': 'Login Realizado!',
                            'message': 'Você será redirecionado para o painel principal.',
                            'redirect': url_for('dashboard')
                        })
                else:
                    return jsonify({
                        'status': 'error',
                        'title': 'Senha Incorreta',
                        'message': 'Senha incorreta. Tente novamente.'
                    }), 401
                
        except Exception as e:
            app.logger.exception("Erro no login:") # Usa app.logger para logar erros completos
            return jsonify({
                'status': 'error',
                'title': 'Erro no Servidor',
                'message': f'Ocorreu um erro inesperado no login.' # Mensagem genérica para o usuário
            }), 500
    
    # Para requisições GET
    return render_template('login.html')

@app.route("/login_admin", methods=["GET", "POST"])
def login_admin():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        
        if email == ADMIN_CREDENTIALS["email"] and password == ADMIN_CREDENTIALS["password"]:
            session['user_id'] = "admin"  
            session['user_admin'] = True
            session['user_nome'] = "Administrador"
            session['consent_given'] = True 
            flash("Login realizado com sucesso!", "success")
            return redirect(url_for("painel_admin"))
        
        flash("Credenciais inválidas!", "error")
        return render_template("login_admin.html")
    return render_template("login_admin.html")

@app.route('/logout')
def logout():
    session.clear()
    flash("Você saiu da sua conta.", "success")
    return redirect(url_for('login'))

# --- Rotas para o modal de consentimento ---
@app.route('/api/initial_consent', methods=['POST'])
def initial_consent():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Sessão expirada ou não autenticado.'}), 401

    user_id = session['user_id']
    data = request.get_json()

    required_consent_ids = [
        'consentDadosCadastro', 'consentReceitasPublicas', 'consentComunidade',
        'consentPersonalizacao', 'consentComComunicacao', 'consentTerceiros',
        'consentFinal'
    ]

    all_accepted = True
    for term_id in required_consent_ids:
        if not data.get(term_id):
            all_accepted = False
            app.logger.debug(f"Termo não aceito: {term_id}") 
            break

    if not all_accepted:
        return jsonify({'success': False, 'error': 'Por favor, aceite todos os termos para continuar.'}), 400

    usuarios_col.update_one(
        {'_id': ObjectId(user_id)},
        {'$set': {'consent_given': True}}
    )

    session.clear() # Limpa a sessão após o consentimento, forçando novo login

    return jsonify({
        'success': True,
        'title': 'Consentimento Registrado!',
        'message': 'Seu consentimento foi registrado. Por favor, faça login novamente para acessar a plataforma.',
        'redirect': url_for('login')
    })

@app.route('/api/check_consent_status')
def check_authentication_and_consent_status():
    authenticated = 'user_id' in session
    consent_given = False
    if authenticated and session.get('user_id') != 'admin': # Admin não precisa de consentimento explícito
        user = usuarios_col.find_one({'_id': ObjectId(session['user_id'])}, {'consent_given': 1})
        if user:
            consent_given = user.get('consent_given', False)
            session['consent_given'] = consent_given # Garante que a sessão está atualizada
    elif authenticated and session.get('user_id') == 'admin':
        consent_given = True 
    
    return jsonify({
        'authenticated': authenticated,
        'consent_given': consent_given,
        'user_nome': session.get('user_nome') if authenticated else None,
        'user_id': session.get('user_id') if authenticated else None
    })

# --- Painel Admin ---
@app.route("/painel_admin")
@admin_required
def painel_admin():
    try:
        total_usuarios = usuarios_col.count_documents({})
        total_receitas = receitas_col.count_documents({})
        total_feedbacks = feedbacks_col.count_documents({})
        feedbacks_nao_lidos = feedbacks_col.count_documents({'lido': False})
        
        usuarios = list(usuarios_col.find().sort("data_cadastro", -1).limit(10))
        for u in usuarios:
            u['_id'] = str(u['_id'])
            if 'telefone' in u and u['telefone']:
                tel = u['telefone']
                if len(tel) == 10:
                    u['telefone_formatado'] = f"({tel[0:2]}) {tel[2:6]}-{tel[6:10]}"
                elif len(tel) == 11:
                    u['telefone_formatado'] = f"({tel[0:2]}) {tel[2:7]}-{tel[7:11]}"
                else:
                    u['telefone_formatado'] = tel
            else:
                u['telefone_formatado'] = 'N/A'

        receitas_com_usuario = []
        for receita in receitas_col.find().sort("data_cadastro", -1).limit(10):
            receita['_id'] = str(receita['_id'])
            usuario = usuarios_col.find_one(
                {'_id': ObjectId(receita['user_id'])},
                {'nome': 1, 'email': 1}
            ) if 'user_id' in receita else None
            
            receitas_com_usuario.append({
                '_id': receita['_id'],
                'titulo': receita.get('titulo', 'Sem título'),
                'categoria': receita.get('categoria', 'Sem categoria'),
                'usuario_nome': usuario['nome'] if usuario else 'Usuário não encontrado',
                'usuario_email': usuario['email'] if usuario else 'N/A',
                'data_cadastro': receita.get('data_cadastro', datetime.now()).strftime("%d/%m/%Y %H:%M")
            })

        feedbacks = list(feedbacks_col.find().sort("data", -1).limit(10))
        for f in feedbacks:
            f['_id'] = str(f['_id'])
            f['data_formatada'] = f['data'].strftime("%d/%m/%Y %H:%M")

        return render_template(
            "painel_admin.html",
            usuarios=usuarios,
            receitas=receitas_com_usuario,
            feedbacks=feedbacks,
            total_usuarios=total_usuarios,
            total_receitas=total_receitas,
            total_feedbacks=total_feedbacks,
            feedbacks_nao_lidos=feedbacks_nao_lidos
        )
        
    except Exception as e:
        app.logger.exception("Erro ao acessar painel administrativo:")
        flash(f"Erro ao acessar painel administrativo.", "error")
        return redirect(url_for("login_admin"))

# --- Rotas de usuários ---
@app.route('/cadastrar_usuario', methods=['GET', 'POST'])
def cadastrar_usuario():
    if request.method == 'POST':
        try:
            nome = request.form.get('nome', '').strip()
            email = request.form.get('email', '').strip().lower()
            telefone = request.form.get('telefone', '').strip()
            senha = request.form.get('senha', '').strip()
            confirmar_senha = request.form.get('confirmar_senha', '').strip()

            if not nome or not re.match(r'^[a-zA-ZÀ-ÿ\s\'-]+$', nome):
                return jsonify({'status': 'error', 'title': 'Nome Inválido', 'message': "Nome inválido. Deve conter apenas letras e espaços"}), 400

            if not email or not validar_email(email):
                return jsonify({'status': 'error', 'title': 'E-mail Inválido', 'message': "Por favor, insira um e-mail válido."}), 400
            
            if usuarios_col.find_one({'email': email}):
                return jsonify({'status': 'error', 'title': 'E-mail Já Cadastrado', 'message': "Este e-mail já está cadastrado."}), 400

            if not validar_telefone(telefone):
                return jsonify({'status': 'error', 'title': 'Telefone Inválido', 'message': "Telefone inválido. Insira DDD + número (10 ou 11 dígitos)."}), 400

            telefone_limpo = re.sub(r'\D', '', telefone)
            if usuarios_col.find_one({'telefone': telefone_limpo}):
                return jsonify({'status': 'error', 'title': 'Telefone Já Cadastrado', 'message': "Este telefone já está cadastrado."}), 400

            if len(senha) < 6:
                return jsonify({'status': 'error', 'title': 'Senha Curta', 'message': "A senha deve ter pelo menos 6 caracteres"}), 400

            if senha != confirmar_senha:
                return jsonify({'status': 'error', 'title': 'Senhas Diferentes', 'message': "As senhas não coincidem."}), 400

            hashed_senha = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt())

            usuario = {
                'nome': nome,
                'email': email,
                'telefone': telefone_limpo,
                'senha': hashed_senha,
                'admin': False,
                'data_cadastro': datetime.now(),
                'ativo': True,
                'consent_given': False 
            }
            
            result = usuarios_col.insert_one(usuario)
            new_user_id = str(result.inserted_id)

            session['user_id'] = new_user_id
            session['user_nome'] = nome
            session['user_admin'] = False
            session['consent_given'] = False 

            return jsonify({
                'status': 'success',
                'title': 'Cadastro Realizado!',
                'message': 'Seu cadastro foi concluído com sucesso. Por favor, aceite os termos para continuar.',
                'redirect': url_for('login', require_consent=True)
            })

        except Exception as e:
            app.logger.exception("Erro no cadastro:")
            return jsonify({
                'status': 'error',
                'title': 'Erro no Servidor',
                'message': f'Ocorreu um erro inesperado no cadastro.'
            }), 500
    
    return render_template('login.html') 


# Rotas de receitas (mantidas do Chefabook)
@app.route('/cadastrar_receita', methods=['GET', 'POST'])
@login_required
def cadastrar_receita():
    if request.method == 'POST':
        titulo = request.form.get('titulo', '').strip()
        categoria = request.form.get('categoria', '').strip()
        ingredientes = request.form.get('ingredientes', '').strip()
        preparo = request.form.get('preparo', '').strip()
        user_id = session['user_id']
        
        if not titulo or not categoria or not ingredientes or not preparo:
            flash("Todos os campos textuais são obrigatórios", "error")
            return redirect(request.url)
        
        imagem_id = None
        file = request.files.get('imagem')
        
        if file and file.filename != '':
            if allowed_file(file.filename):
                try:
                    imagem_id = fs.put(file, filename=secure_filename(file.filename))
                except Exception as e:
                    flash(f"Erro ao processar imagem: {str(e)}", "error")
                    return redirect(request.url)
            else:
                flash("Tipo de arquivo não permitido. Use PNG, JPG ou JPEG.", "error")
                return redirect(request.url)
        
        try:
            receita = {
                'titulo': titulo,
                'categoria': categoria,
                'ingredientes': ingredientes,
                'preparo': preparo,
                'user_id': user_id,
                'data_cadastro': datetime.now()
            }
            
            if imagem_id:
                receita['imagem_id'] = imagem_id
                
            receitas_col.insert_one(receita)
            
            flash("Receita cadastrada com sucesso!", "success")
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            flash(f"Erro ao cadastrar receita: {str(e)}", "error")

    return render_template('cadastrar_receitas.html')

@app.route('/visualizar_receitas')
@login_required
def visualizar_receitas():
    try:
        receitas = []
        for receita in receitas_col.find({'user_id': session['user_id']}):
            receitas.append({
                'id': str(receita['_id']),
                'titulo': receita['titulo'],
                'categoria': receita['categoria'],
                'ingredientes': receita['ingredientes'],
                'preparo': receita['preparo'],
                'user_id': receita['user_id'],
                'tem_imagem': 'imagem_id' in receita
            })

        return render_template('visualizar_receitas.html', receitas=receitas)
        
    except Exception as e:
        flash(f"Erro ao carregar receitas: {str(e)}", "error")
        return redirect(url_for('dashboard'))

@app.route('/imagem_receita/<receita_id>')
@login_required
def imagem_receita(receita_id):
    try:
        receita = receitas_col.find_one({'_id': ObjectId(receita_id), 'user_id': session['user_id']})
        
        if receita and 'imagem_id' in receita:
            imagem = fs.get(receita['imagem_id'])
            response = make_response(imagem.read())
            response.headers.set('Content-Type', 'image/jpeg')
            return response
        
    except Exception as e:
        app.logger.exception("Erro ao carregar imagem:")
    
    # Caminho corrigido para fallback de imagem
    return send_from_directory(os.path.join(app.root_path, 'static', 'images'), 'sem-imagem.jpg') 

@app.route('/editar_receita/<receita_id>', methods=['GET', 'POST'])
@login_required
def editar_receita(receita_id):
    try:
        receita = receitas_col.find_one({'_id': ObjectId(receita_id), 'user_id': session['user_id']})
        
        if not receita:
            flash("Receita não encontrada ou você não tem permissão para editá-la", "error")
            return redirect(url_for('visualizar_receitas'))
        
        if request.method == 'POST':
            titulo = request.form.get('titulo', '').strip()
            categoria = request.form.get('categoria', '').strip()
            ingredientes = request.form.get('ingredientes', '').strip()
            preparo = request.form.get('preparo', '').strip()
            
            update_data = {
                'titulo': titulo,
                'categoria': categoria,
                'ingredientes': ingredientes,
                'preparo': preparo
            }
            
            if 'imagem' in request.files:
                file = request.files['imagem']
                if file and file.filename != '' and allowed_file(file.filename):
                    if 'imagem_id' in receita:
                        fs.delete(receita['imagem_id'])
                    update_data['imagem_id'] = fs.put(file, filename=secure_filename(file.filename))

            receitas_col.update_one(
                {'_id': ObjectId(receita_id)},
                {'$set': update_data}
            )
            
            flash("Receita atualizada com sucesso!", "success")
            return redirect(url_for('visualizar_receitas'))
        
        return render_template('editar_receita.html', receita=receita)
        
    except Exception as e:
        app.logger.exception("Erro ao editar receita:")
        flash(f"Erro ao editar receita.", "error")
        return redirect(url_for('visualizar_receitas'))

@app.route('/excluir_receita/<receita_id>', methods=['POST'])
@login_required
def excluir_receita(receita_id):
    try:
        receita = receitas_col.find_one({'_id': ObjectId(receita_id), 'user_id': session['user_id']})
        
        if not receita:
            flash("Receita não encontrada ou você não tem permissão para excluí-la", "error")
            return redirect(url_for('visualizar_receitas'))
        
        if 'imagem_id' in receita:
            fs.delete(receita['imagem_id'])
            
        receitas_col.delete_one({'_id': ObjectId(receita_id)})
        flash("Receita excluída com sucesso!", "success")
        
    except Exception as e:
        app.logger.exception("Erro ao excluir receita:")
        flash(f"Erro ao excluir receita.", "error")
    
    return redirect(url_for('visualizar_receitas'))

# Admin - Gerenciamento de Usuários
@app.route("/editar_usuario_admin/<usuario_id>", methods=["GET", "POST"])
@admin_required
def editar_usuario_admin(usuario_id):
    try:
        usuario = usuarios_col.find_one({'_id': ObjectId(usuario_id)})
        
        if not usuario:
            flash("Usuário não encontrado.", "error")
            return redirect(url_for("painel_admin"))

        if request.method == "POST":
            nome = request.form.get("nome", "").strip()
            email = request.form.get("email", "").strip().lower()
            telefone = request.form.get("telefone", "").strip()

            if not nome or not email:
                flash("Nome e e-mail são obrigatórios.", "error")
                return redirect(url_for("editar_usuario_admin", usuario_id=usuario_id))

            if not validar_email(email):
                flash("E-mail inválido.", "error")
                return redirect(url_for("editar_usuario_admin", usuario_id=usuario_id))

            if not validar_telefone(telefone):
                flash("Telefone inválido.", "error")
                return redirect(url_for("editar_usuario_admin", usuario_id=usuario_id))

            telefone_limpo = re.sub(r'\D', '', telefone)

            if usuarios_col.find_one({'email': email, '_id': {'$ne': ObjectId(usuario_id)}}):
                flash("Este e-mail já está em uso.", "error")
                return redirect(url_for("editar_usuario_admin", usuario_id=usuario_id))

            update_data = {
                'nome': nome,
                'email': email,
                'telefone': telefone_limpo,
                'data_atualizacao': datetime.now()
            }

            usuarios_col.update_one(
                {'_id': ObjectId(usuario_id)},
                {'$set': update_data}
            )

            flash("Usuário atualizado com sucesso!", "success")
            return redirect(url_for("painel_admin"))

        return render_template("editar_usuario_admin.html", usuario=usuario)
        
    except Exception as e:
        app.logger.exception("Erro ao editar usuário:")
        flash(f"Erro ao editar usuário.", "error")
        return redirect(url_for("painel_admin"))

@app.route("/excluir_usuario/<usuario_id>", methods=["POST"])
@admin_required
def excluir_usuario(usuario_id):
    try:
        receitas_col.delete_many({'user_id': usuario_id})
        usuarios_col.delete_one({'_id': ObjectId(usuario_id)})
        
        flash("Usuário e suas receitas foram excluídos.", "success")
    except Exception as e:
        app.logger.exception("Erro ao excluir usuário:")
        flash(f"Erro ao excluir usuário.", "error")
    
    return redirect(url_for("painel_admin"))

# Admin - Gerenciamento de Receitas
@app.route("/editar_receita_admin/<receita_id>", methods=["GET", "POST"])
@admin_required
def editar_receita_admin(receita_id):
    try:
        receita = receitas_col.find_one({'_id': ObjectId(receita_id)})
        
        if not receita:
            flash("Receita não encontrada.", "error")
            return redirect(url_for("painel_admin"))

        usuario = usuarios_col.find_one(
            {'_id': ObjectId(receita['user_id'])},
            {'nome': 1, 'email': 1}
        ) if 'user_id' in receita else None

        if request.method == "POST":
            titulo = request.form.get("titulo", "").strip()
            categoria = request.form.get("categoria", "").strip()
            ingredientes = request.form.get("ingredientes", "").strip()
            preparo = request.form.get("preparo", "").strip()

            if not titulo or not categoria or not ingredientes or not preparo:
                flash("Todos os campos são obrigatórios.", "error")
                return redirect(url_for("editar_receita_admin", receita_id=receita_id))

            update_data = {
                'titulo': titulo,
                'categoria': categoria,
                'ingredientes': ingredientes,
                'preparo': preparo,
                'data_atualizacao': datetime.now()
            }

            if 'imagem' in request.files:
                file = request.files['imagem']
                if file and file.filename != '' and allowed_file(file.filename):
                    if 'imagem_id' in receita:
                        fs.delete(receita['imagem_id'])
                    update_data['imagem_id'] = fs.put(file, filename=secure_filename(file.filename))

            receitas_col.update_one(
                {'_id': ObjectId(receita_id)},
                {'$set': update_data}
            )

            flash("Receita atualizada com sucesso!", "success")
            return redirect(url_for("painel_admin"))

        return render_template(
            "editar_receita_admin.html",
            receita=receita,
            usuario_nome=usuario['nome'] if usuario else 'Usuário não encontrado'
        )
        
    except Exception as e:
        app.logger.exception("Erro ao editar receita (admin):")
        flash(f"Erro ao editar receita.", "error")
        return redirect(url_for("painel_admin"))

@app.route("/excluir_receita_admin/<receita_id>", methods=["POST"])
@admin_required
def excluir_receita_admin(receita_id):
    try:
        receita = receitas_col.find_one({'_id': ObjectId(receita_id)})
        
        if receita and 'imagem_id' in receita:
            fs.delete(receita['imagem_id'])
            
        receitas_col.delete_one({'_id': ObjectId(receita_id)})
        flash("Receita excluída com sucesso.", "success")
    except Exception as e:
        app.logger.exception("Erro ao excluir receita (admin):")
        flash(f"Erro ao excluir receita.", "error")
    
    return redirect(url_for("painel_admin"))

# --- Rotas de Recuperação de Senha ---
# Rota para exibir o formulário de recuperação de senha (GET)
@app.route('/recuperar_senha')
def recuperar_senha():
    return render_template('recuperar_senha.html')

# Rota para processar a solicitação de recuperação de senha (POST)
@app.route('/recover_password', methods=['POST'])
def recover_password():
    identifier = request.form.get('recoveryIdentifier')
    user = usuarios_col.find_one({'$or': [{'email': identifier}, {'nome': identifier}]}) # Busca por email ou nome

    if user:
        # Em um ambiente real, aqui você geraria um token de redefinição,
        # o armazenaria no banco de dados e enviaria um e-mail com o link de redefinição.
        app.logger.info(f"Solicitação de recuperação simulada para: {identifier}. E-mail de recuperação simulado enviado para {user['email']}")
        return jsonify({
            'status': 'success',
            'title': 'E-mail Enviado',
            'message': 'Seu link de redefinição de senha foi enviado para o e-mail cadastrado. Verifique sua caixa de entrada (e a pasta de spam).',
            'redirect': url_for('login')
        })
    else:
        return jsonify({
            'status': 'error',
            'title': 'Usuário não encontrado',
            'message': 'Nenhum usuário ou e-mail encontrado com este identificador. Por favor, tente novamente.'
        })


@app.route('/enviar_feedback', methods=['GET', 'POST'])
@login_required
def enviar_feedback():
    if request.method == 'POST':
        try:
            tipo = request.form.get('tipo', '').strip()
            mensagem = request.form.get('mensagem', '').strip()
            avaliacao = int(request.form.get('avaliacao', 0))
            
            if not mensagem or len(mensagem) < 10:
                flash("Por favor, escreva uma mensagem mais detalhada (mínimo 10 caracteres)", "error")
                return redirect(url_for('enviar_feedback'))
            
            if avaliacao < 1 or avaliacao > 5:
                flash("Por favor, selecione uma avaliação entre 1 e 5 estrelas", "error")
                return redirect(url_for('enviar_feedback'))
            
            feedback = {
                'user_id': session['user_id'],
                'user_nome': session['user_nome'],
                'tipo': tipo,
                'mensagem': mensagem,
                'avaliacao': avaliacao,
                'data': datetime.now(),
                'lido': False
            }
            
            feedbacks_col.insert_one(feedback)
            
            flash("Obrigado pelo seu feedback! Valorizamos sua opinião.", "success")
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            app.logger.exception("Erro ao enviar feedback:")
            flash(f"Erro ao enviar feedback.", "error")
            return redirect(url_for('enviar_feedback'))
    
    return render_template('enviar_feedback.html')

@app.route('/admin/feedbacks')
@admin_required
def visualizar_feedbacks():
    try:
        feedbacks = list(feedbacks_col.find().sort("data", -1))
        
        return render_template('painel_admin.html', 
                               feedbacks=feedbacks,
                               total_feedbacks=feedbacks_col.count_documents({}),
                               feedbacks_nao_lidos=feedbacks_col.count_documents({'lido': False}))
        
    except Exception as e:
        app.logger.exception("Erro ao carregar feedbacks (admin):")
        flash(f"Erro ao carregar feedbacks.", "error")
        return redirect(url_for('painel_admin'))

@app.route('/admin/marcar_lido/<feedback_id>', methods=['POST'])
@admin_required
def marcar_feedback_lido(feedback_id):
    try:
        feedbacks_col.update_one(
            {'_id': ObjectId(feedback_id)},
            {'$set': {'lido': True}}
        )
        flash("Feedback marcado como lido", "success")
    except Exception as e:
        app.logger.exception("Erro ao atualizar feedback:")
        flash(f"Erro ao atualizar feedback.", "error")
    
    return redirect(url_for('painel_admin'))

# Rotas de erro
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    app.logger.exception("Erro Interno do Servidor (500):") 
    return render_template('500.html'), 500

# --- Execução da Aplicação ---
if __name__ == '__main__':
    # Cria as pastas de upload se elas não existirem
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['PROFILE_PICS_FOLDER'], exist_ok=True)
    os.makedirs(app.config['IMAGES_FOLDER'], exist_ok=True)
    app.run(debug=False) # Mude para True para depurar localmente
