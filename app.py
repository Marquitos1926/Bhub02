from flask import Flask, request, jsonify, redirect, url_for, render_template, session, send_from_directory
import re
import os
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta, datetime
from pymongo import MongoClient
from bson.objectid import ObjectId
from bson import json_util
import json
import requests # Import the requests library

app = Flask(__name__)

# --- Configurações da Aplicação ---
# Em produção, a chave secreta deve ser carregada de uma variável de ambiente.
# Isso garante que a chave é persistente e segura.
app.secret_key = os.environ.get('FLASK_SECRET_KEY', os.urandom(24))

app.config['UPLOAD_FOLDER'] = 'static/uploads' # Pasta para uploads de posts
app.config['PROFILE_PICS_FOLDER'] = 'static/profile_pics' # Pasta para fotos de perfil
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'} # Extensões de arquivo permitidas

# --- Conexão com MongoDB ---
# É uma boa prática armazenar a URI em uma variável de ambiente para produção.
mongo_uri = os.environ.get("MONGO_URI", "mongodb+srv://juliocardoso:z5fTsL8EAgD8SORa@dbbhub.nxcw2n9.mongodb.net/?retryWrites=true&w=majority")
client = MongoClient(mongo_uri)
db = client.get_database("dbbhub")

# --- Coleções do Banco de Dados ---
users_collection = db.users
cnpjs_collection = db.cnpjs # Usado para controle de CNPJs já cadastrados
posts_collection = db.posts
companies_collection = db.companies

# --- Funções Auxiliares (Helpers) para Validação ---
def validate_username(username):
    """
    Valida o formato do nome de usuário.
    Permite letras, números, pontos, traços e underscores.
    Define limites de tamanho.
    """
    pattern = r'^[a-zA-Z0-9_.-]+$'
    if not re.match(pattern, username):
        return False, "Nome de usuário inválido", "Pode conter apenas letras, números, pontos, traços e underscores."
    if len(username) < 4:
        return False, "Nome muito curto", "Deve ter pelo menos 4 caracteres."
    if len(username) > 20:
        return False, "Nome muito longo", "Deve ter no máximo 20 caracteres."
    return True, "", ""

def validate_email(email):
    """
    Valida o formato de um endereço de e-mail.
    """
    pattern = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
    if not re.match(pattern, email):
        return False, "Email inválido", "Por favor, insira um e-mail válido."
    return True, "", ""

def validate_password(password):
    """
    Valida o comprimento mínimo da senha.
    """
    if len(password) < 8:
        return False, "Senha muito curta", "A senha deve ter no mínimo 8 caracteres."
    return True, "", ""

def validate_phone(phone):
    """
    Valida o formato do telefone (apenas dígitos, com DDD).
    Permite 10 ou 11 dígitos.
    """
    # Remove qualquer caractere que não seja dígito do telefone
    phone = ''.join(filter(str.isdigit, phone))
    if len(phone) < 10 or len(phone) > 11:
        return False, "Telefone inválido", "Use DDD + número (10 ou 11 dígitos)."
    return True, "", ""

def validate_cnpj(cnpj):
    """
    Validação básica de CNPJ.
    Verifica se contém 14 dígitos após remover não-dígitos.
    Para validação completa, seria necessário implementar o algoritmo de validação de CNPJ.
    """
    # Remove qualquer caractere que não seja dígito do CNPJ
    cnpj = ''.join(filter(str.isdigit, cnpj))
    if len(cnpj) != 14:
        return False, "CNPJ inválido", "O CNPJ deve conter 14 dígitos."
    return True, "", ""

def allowed_file(filename):
    """
    Verifica se a extensão do arquivo é permitida.
    """
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def get_user_data(username):
    """
    Obtém os dados completos de um usuário pelo nome de usuário.
    Converte o ObjectId para string e define uma imagem de perfil padrão se não houver.
    """
    user = users_collection.find_one({'username': username})
    if user:
        user['_id'] = str(user['_id'])
        if 'profile_pic' not in user or not user['profile_pic']:
            user['profile_pic'] = 'user-icon-pequeno.png' # Imagem de perfil padrão
    return user

# --- Rotas Principais da Aplicação ---
@app.route('/')
def home():
    """
    Redireciona para o índice se o usuário estiver logado,
    caso contrário, redireciona para a página de login.
    """
    if 'username' in session:
        return redirect(url_for('index'))
    return redirect(url_for('login'))

@app.route('/index')
def index():
    """
    Renderiza a página principal (feed de posts) se o usuário estiver autenticado.
    Busca os posts mais recentes e os dados do usuário logado.
    """
    if 'username' not in session:
        return redirect(url_for('login'))

    user = get_user_data(session['username'])
    if not user:
        # Se o usuário não for encontrado no DB, limpa a sessão e redireciona para login
        session.clear()
        return redirect(url_for('login'))

    # Busca os 10 posts mais recentes, ordenados por data de criação
    posts = list(posts_collection.find().sort('created_at', -1).limit(10))

    # Processa os posts para garantir que IDs são strings e que há uma foto de perfil para o autor
    for post in posts:
        post['_id'] = str(post['_id'])
        post['author_id'] = str(post['author_id'])

        author_user = users_collection.find_one({'_id': ObjectId(post['author_id'])})
        if author_user and 'profile_pic' in author_user and author_user['profile_pic']:
            post['author_profile_pic'] = author_user['profile_pic']
        else:
            post['author_profile_pic'] = 'user-icon-pequeno.png'

    return render_template('index.html',
                           username=session['username'],
                           user=user,
                           posts=posts)

@app.route('/explore')
def explore():
    """
    Renderiza a página de exploração, exibindo empresas e outros usuários.
    """
    if 'username' not in session:
        return redirect(url_for('login'))

    user = get_user_data(session['username'])
    if not user:
        session.clear()
        return redirect(url_for('login'))

    # Busca as 20 primeiras empresas
    companies = list(companies_collection.find().limit(20))
    for company in companies:
        company['_id'] = str(company['_id'])

    # Busca todos os usuários (apenas username e profile_pic)
    all_users = list(users_collection.find({}, {'username': 1, 'profile_pic': 1}))
    for u in all_users:
        u['_id'] = str(u['_id'])
        if 'profile_pic' not in u or not u['profile_pic']:
            u['profile_pic'] = 'user-icon-pequeno.png'

    return render_template('explore.html',
                           username=session['username'],
                           user=user,
                           companies=companies,
                           all_users=all_users)

# --- Endpoints da API ---
@app.route('/api/companies')
def api_companies():
    """
    Endpoint para retornar uma lista de empresas em formato JSON.
    Requer autenticação.
    """
    if 'username' not in session:
        return jsonify({'error': 'Não autenticado'}), 401

    companies = list(companies_collection.find({}, {'name': 1, 'description': 1, 'logo': 1}))
    for company in companies:
        company['_id'] = str(company['_id'])

    # Usa json_util.dumps para lidar com ObjectIds do MongoDB e depois carrega como JSON normal
    return json.loads(json_util.dumps(companies))

@app.route('/api/posts')
def api_posts():
    """
    Endpoint para retornar uma lista de posts em formato JSON.
    Requer autenticação.
    """
    if 'username' not in session:
        return jsonify({'error': 'Não autenticado'}), 401

    posts = list(posts_collection.find().sort('created_at', -1).limit(10))
    for post in posts:
        post['_id'] = str(post['_id'])
        post['author_id'] = str(post['author_id'])

        author_user = users_collection.find_one({'_id': ObjectId(post['author_id'])})
        if author_user and 'profile_pic' in author_user and author_user['profile_pic']:
            post['author_profile_pic'] = author_user['profile_pic']
        else:
            post['author_profile_pic'] = 'user-icon-pequeno.png'

    return json.loads(json_util.dumps(posts))

@app.route('/api/create_post', methods=['POST'])
def create_post():
    """
    Endpoint para criar um novo post.
    Permite conteúdo de texto e/ou imagem.
    Requer autenticação.
    """
    if 'username' not in session:
        return jsonify({'error': 'Não autenticado'}), 401

    content = request.form.get('content')
    user_id = session.get('user_id')
    username = session.get('username')

    # Obtém a foto de perfil do usuário para o post
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    profile_pic = user.get('profile_pic', 'user-icon-pequeno.png') if user else 'user-icon-pequeno.png'

    if not content and not request.files:
        return jsonify({'error': 'Conteúdo ou imagem é necessário para criar um post.'}), 400

    post_data = {
        'author_id': user_id,
        'author_name': username,
        'author_profile_pic': profile_pic,
        'content': content,
        'created_at': datetime.now(),
        'likes': [],
        'comments': [],
        'image': None
    }

    # Lida com o upload da imagem do post
    if 'image' in request.files:
        file = request.files['image']
        if file and allowed_file(file.filename):
            # Gera um nome de arquivo único para a imagem
            filename = f"{session['user_id']}_{int(datetime.now().timestamp())}.{file.filename.rsplit('.', 1)[1].lower()}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            post_data['image'] = filename

    posts_collection.insert_one(post_data)
    return jsonify({'success': 'Post criado com sucesso!'})

@app.route('/api/like_post/<post_id>', methods=['POST'])
def like_post(post_id):
    """
    Endpoint para dar ou remover um "curtir" (like) de um post.
    Requer autenticação.
    """
    if 'username' not in session:
        return jsonify({'error': 'Não autenticado'}), 401

    user_id = session['user_id']

    try:
        post = posts_collection.find_one({'_id': ObjectId(post_id)})
        if not post:
            return jsonify({'error': 'Post não encontrado.'}), 404

        if user_id in post.get('likes', []):
            # Se o usuário já curtiu, remove o like
            posts_collection.update_one(
                {'_id': ObjectId(post_id)},
                {'$pull': {'likes': user_id}}
            )
            return jsonify({'success': 'Curtida removida.'})
        else:
            # Se o usuário não curtiu, adiciona o like
            posts_collection.update_one(
                {'_id': ObjectId(post_id)},
                {'$push': {'likes': user_id}}
            )
            return jsonify({'success': 'Post curtido!'})
    except Exception as e:
        return jsonify({'error': f'Erro ao processar like: {str(e)}'}), 500

# --- Rotas de Autenticação ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Lida com o login de usuários.
    GET: Exibe a página de login.
    POST: Processa as credenciais e autentica o usuário.
    """
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('rememberMe') == 'on' # Lembre-me checkbox

        if not username or not password:
            return jsonify({
                'status': 'error',
                'title': 'Campos vazios',
                'message': 'Por favor, preencha ambos os campos.'
            }), 400

        user = users_collection.find_one({'username': username})

        if not user or not check_password_hash(user['password'], password):
            return jsonify({
                'status': 'error',
                'title': 'Falha no login',
                'message': 'Credenciais inválidas.'
            }), 401

        # Autenticação bem-sucedida
        session['username'] = username
        session['user_id'] = str(user['_id'])
        if remember:
            session.permanent = True
            app.permanent_session_lifetime = timedelta(days=30) # Sessão permanente por 30 dias

        return jsonify({
            'status': 'success',
            'title': 'Login bem-sucedido',
            'message': 'Você será redirecionado...',
            'redirect': url_for('index')
        })

    # Para requisições GET, renderiza o template de login
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Lida com o registro de novos usuários.
    GET: Exibe a página de registro (geralmente via a página de login).
    POST: Processa os dados de registro, valida-os e cria um novo usuário.
    """
    if request.method == 'POST':
        username = request.form.get('newUsername')
        password = request.form.get('newPassword')
        email = request.form.get('email')
        phone = request.form.get('phone')
        cnpj = request.form.get('cnpj')

        # Validação de campos obrigatórios
        if not all([username, password, email]):
            return jsonify({
                'status': 'error',
                'title': 'Campos obrigatórios',
                'message': 'Preencha todos os campos obrigatórios.'
            }), 400

        # Validação do nome de usuário
        is_valid, title, message = validate_username(username)
        if not is_valid:
            return jsonify({
                'status': 'error',
                'title': title,
                'message': message
            }), 400

        if users_collection.find_one({'username': username}):
            return jsonify({
                'status': 'error',
                'title': 'Nome em uso',
                'message': 'Este nome de usuário já está sendo usado.'
            }), 400

        # Validação do e-mail
        is_valid, title, message = validate_email(email)
        if not is_valid:
            return jsonify({
                'status': 'error',
                'title': title,
                'message': message
            }), 400

        if users_collection.find_one({'email': email}):
            return jsonify({
                'status': 'error',
                'title': 'Email em uso',
                'message': 'Este email já está cadastrado.'
            }), 400

        # Validação da senha
        is_valid, title, message = validate_password(password)
        if not is_valid:
            return jsonify({
                'status': 'error',
                'title': title,
                'message': message
            }), 400

        # Validação e tratamento do CNPJ (se fornecido)
        if cnpj and cnpj.strip(): # Verifica se o campo CNPJ não está vazio e não contém apenas espaços
            formatted_cnpj = ''.join(filter(str.isdigit, cnpj)) # Remove não-dígitos
            is_valid, title, message = validate_cnpj(formatted_cnpj)
            if not is_valid:
                return jsonify({
                    'status': 'error',
                    'title': title,
                    'message': message
                }), 400

            if cnpjs_collection.find_one({'cnpj': formatted_cnpj}):
                return jsonify({
                    'status': 'error',
                    'title': 'CNPJ em uso',
                    'message': 'Este CNPJ já está cadastrado.'
                }), 400

            # Se o CNPJ é válido e único, insere na coleção de CNPJs
            cnpjs_collection.insert_one({'cnpj': formatted_cnpj})
        else:
            formatted_cnpj = None # Define como None se o CNPJ não for fornecido

        # Validação e tratamento do telefone (se fornecido)
        if phone and phone.strip():
            formatted_phone = ''.join(filter(str.isdigit, phone))
            is_valid, title, message = validate_phone(formatted_phone)
            if not is_valid:
                return jsonify({
                    'status': 'error',
                    'title': title,
                    'message': message
                }), 400
        else:
            formatted_phone = None # Define como None se o telefone não for fornecido

        # Criação dos dados do novo usuário
        user_data = {
            'username': username,
            'password': generate_password_hash(password), # Hash da senha para segurança
            'email': email,
            'phone': formatted_phone,
            'cnpj': formatted_cnpj,
            'created_at': datetime.now(),
            'consent_given': False, # Consentimento inicial
            'profile_pic': 'user-icon-pequeno.png' # Foto de perfil padrão
        }

        result = users_collection.insert_one(user_data)

        # Se um CNPJ foi fornecido, cria uma entrada de empresa associada
        if formatted_cnpj:
            company_data = {
                'name': username, # Nome inicial da empresa pode ser o nome de usuário
                'cnpj': formatted_cnpj,
                'description': f'Empresa de {username} no BusinessHub',
                'logo': 'company-default.png', # Logo padrão
                'owner_id': str(result.inserted_id), # Associa a empresa ao ID do usuário
                'created_at': datetime.now()
            }
            companies_collection.insert_one(company_data)

        return jsonify({
            'status': 'success',
            'title': 'Cadastro realizado!',
            'message': 'Seu cadastro foi concluído com sucesso.',
            'redirect': url_for('login')
        })

    return render_template('login.html') # A página de registro geralmente é acessada a partir do login

@app.route('/consent', methods=['POST'])
def consent():
    """
    Endpoint para registrar o consentimento do usuário.
    Verifica se todos os termos obrigatórios foram aceitos.
    """
    required_consents = [
        'consentCadastro', 'consentPerfilVisualizacao', 'consentPerfilParcerias',
        'consentPostagens', 'consentParcerias', 'consentChat',
        'consentContratosArmazenamento', 'consentContratosConfirmacao'
    ]

    if all(request.form.get(consent) == 'on' for consent in required_consents):
        if 'user_id' in session:
            users_collection.update_one(
                {'_id': ObjectId(session['user_id'])},
                {'$set': {'consent_given': True}}
            )
            session['consent_given'] = True # Atualiza o status na sessão
        return jsonify({'success': 'Consentimento registrado.'})
    return jsonify({'error': 'Aceite todos os termos para continuar.'}), 400

@app.route('/logout')
def logout():
    """
    Encerra a sessão do usuário e redireciona para a página de login.
    """
    session.clear() # Limpa todos os dados da sessão
    return redirect(url_for('login'))

# --- Rotas de Perfil ---
@app.route('/perfil')
def show_profile():
    """
    Exibe a página de perfil do usuário logado.
    Busca os dados do usuário e, se aplicável, da empresa associada.
    """
    if 'username' not in session:
        return redirect(url_for('login'))

    user = get_user_data(session['username'])
    if not user:
        session.clear()
        return redirect(url_for('login'))

    # BUSCAR INFORMAÇÕES DA EMPRESA SE O USUÁRIO TIVER UM CNPJ CADASTRADO
    company = None
    if 'cnpj' in user and user['cnpj']:
        # O owner_id na coleção 'companies' é uma string do ObjectId do usuário
        company = companies_collection.find_one({'owner_id': user['_id']})
        # Convertemos o ObjectId da empresa para string, se existir
        if company:
            company['_id'] = str(company['_id'])

    return render_template('perfil.html', user=user, company=company) # Passa 'company' para o template

@app.route('/api/update_profile', methods=['POST'])
def update_profile():
    """
    Endpoint para atualizar os dados do perfil do usuário.
    Permite atualizar username, email, cnpj, telefone e foto de perfil.
    """
    if 'user_id' not in session:
        return jsonify({'status': 'error', 'message': 'Não autenticado'}), 401

    user_id = session['user_id']
    current_user_doc = users_collection.find_one({'_id': ObjectId(user_id)})
    if not current_user_doc:
        return jsonify({'status': 'error', 'message': 'Usuário não encontrado'}), 404

    new_username = request.form.get('username')
    new_email = request.form.get('email')
    new_cnpj = request.form.get('cnpj')
    new_phone = request.form.get('phone')

    update_data = {}

    # Atualização do Username
    if new_username and new_username != current_user_doc.get('username'):
        is_valid, title, message = validate_username(new_username)
        if not is_valid:
            return jsonify({'status': 'error', 'message': f"{title}: {message}"}), 400
        if users_collection.find_one({'username': new_username, '_id': {'$ne': ObjectId(user_id)}}):
            return jsonify({'status': 'error', 'message': 'Este nome de usuário já está em uso.'}), 400
        update_data['username'] = new_username
        session['username'] = new_username # Atualiza o username na sessão

    # Atualização do Email
    if new_email and new_email != current_user_doc.get('email'):
        is_valid, title, message = validate_email(new_email)
        if not is_valid:
            return jsonify({'status': 'error', 'message': f"{title}: {message}"}), 400
        if users_collection.find_one({'email': new_email, '_id': {'$ne': ObjectId(user_id)}}):
            return jsonify({'status': 'error', 'message': 'Este e-mail já está cadastrado.'}), 400
        update_data['email'] = new_email

    # Atualização do CNPJ
    # Certifica-se de que o CNPJ é uma string e remove não-dígitos, ou é None se o campo for vazio
    processed_new_cnpj = ''.join(filter(str.isdigit, new_cnpj)) if new_cnpj else None
    current_cnpj = current_user_doc.get('cnpj')

    if processed_new_cnpj != current_cnpj:
        if processed_new_cnpj: # Se um novo CNPJ foi fornecido e não está vazio
            is_valid, title, message = validate_cnpj(processed_new_cnpj)
            if not is_valid:
                return jsonify({'status': 'error', 'message': f"{title}: {message}"}), 400
            # Verifica se o CNPJ já está sendo usado por outro usuário
            # Adicionado o 'user_id': {'$ne': ObjectId(user_id)} para permitir que o próprio usuário mantenha seu CNPJ
            if cnpjs_collection.find_one({'cnpj': processed_new_cnpj, 'user_id': {'$ne': ObjectId(user_id)} if user_id else {'$exists': False}}):
                return jsonify({'status': 'error', 'message': 'Este CNPJ já está cadastrado para outro usuário.'}), 400

            update_data['cnpj'] = processed_new_cnpj
            # Atualiza ou insere o CNPJ na coleção de cnpjs_collection associado ao user_id
            cnpjs_collection.update_one(
                {'user_id': ObjectId(user_id)},
                {'$set': {'cnpj': processed_new_cnpj, 'user_id': ObjectId(user_id)}},
                upsert=True
            )
            # Atualiza ou cria a empresa na companies_collection
            companies_collection.update_one(
                {'owner_id': user_id}, # owner_id é uma string aqui, como você a armazena
                {'$set': {
                    'cnpj': processed_new_cnpj,
                    'name': current_user_doc.get('username', 'Empresa'), # Mantém o nome atual ou padrão
                    'updated_at': datetime.now()
                }},
                upsert=True
            )
        else: # Se o CNPJ foi removido (campo vazio)
            update_data['cnpj'] = None
            cnpjs_collection.delete_one({'user_id': ObjectId(user_id)})
            companies_collection.delete_one({'owner_id': user_id})


    # Atualização do Telefone
    # Certifica-se de que o telefone é uma string e remove não-dígitos, ou é None se o campo for vazio
    processed_new_phone = ''.join(filter(str.isdigit, new_phone)) if new_phone else None
    current_phone = current_user_doc.get('phone')

    if processed_new_phone != current_phone:
        if processed_new_phone: # Se um novo telefone foi fornecido e não está vazio
            is_valid, title, message = validate_phone(processed_new_phone)
            if not is_valid:
                return jsonify({'status': 'error', 'message': f"{title}: {message}"}), 400
            update_data['phone'] = processed_new_phone
        else: # Se o telefone foi removido (campo vazio)
            update_data['phone'] = None

    # Atualização da foto de perfil
    if 'profile_pic' in request.files:
        file = request.files['profile_pic']
        if file.filename != '' and allowed_file(file.filename):
            # Gera um nome de arquivo único
            filename = f"{user_id}_{int(datetime.now().timestamp())}.{file.filename.rsplit('.', 1)[1].lower()}"
            filepath = os.path.join(app.config['PROFILE_PICS_FOLDER'], filename)
            file.save(filepath)
            update_data['profile_pic'] = filename

            # Remove a foto antiga se não for a padrão
            old_pic = current_user_doc.get('profile_pic')
            if old_pic and old_pic != 'user-icon-pequeno.png' and \
               os.path.exists(os.path.join(app.config['PROFILE_PICS_FOLDER'], old_pic)):
                os.remove(os.path.join(app.config['PROFILE_PICS_FOLDER'], old_pic))
        elif file.filename == '' and current_user_doc.get('profile_pic') != 'user-icon-pequeno.png':
            # Se o campo de upload estiver vazio e o usuário tinha uma foto não padrão,
            # define a foto padrão e remove a antiga
            update_data['profile_pic'] = 'user-icon-pequeno.png'
            old_pic = current_user_doc.get('profile_pic')
            if old_pic and old_pic != 'user-icon-pequeno.png' and \
               os.path.exists(os.path.join(app.config['PROFILE_PICS_FOLDER'], old_pic)):
                os.remove(os.path.join(app.config['PROFILE_PICS_FOLDER'], old_pic))

    if update_data:
        users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': update_data}
        )
        return jsonify({'status': 'success', 'message': 'Perfil atualizado com sucesso!'})
    else:
        return jsonify({'status': 'info', 'message': 'Nenhuma alteração a ser salva.'})

# --- Rotas de Recuperação de Senha ---
@app.route('/recuperar_senha')
def show_recover_password():
    """
    Exibe a página de recuperação de senha.
    """
    return render_template('recuperar_senha.html')

@app.route('/recover_password', methods=['POST'])
def recover_password():
    """
    Lida com a solicitação de recuperação de senha.
    Simula o envio de um e-mail de redefinição.
    """
    identifier = request.form.get('recoveryIdentifier')
    user = users_collection.find_one({'$or': [{'email': identifier}, {'username': identifier}]})

    if user:
        # Em um ambiente real, aqui você geraria um token de redefinição,
        # o armazenaria no banco de dados e enviaria um e-mail com o link de redefinição.
        print(f"DEBUG: Solicitação de recuperação para: {identifier}. E-mail de recuperação simulado enviado para {user['email']}")
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

# --- Rotas para Arquivos Estáticos ---
@app.route('/static/<path:filename>')
def static_files(filename):
    """
    Serve arquivos estáticos da pasta 'static'.
    """
    return send_from_directory('static', filename)

# --- Verificação de Autenticação para Frontend (API) ---
@app.route('/api/check-auth')
def check_auth():
    """
    Endpoint para o frontend verificar rapidamente o status de autenticação.
    """
    return jsonify({
        'authenticated': 'username' in session,
        'username': session.get('username', '')
    })

@app.route('/api/update_profile_pic', methods=['POST'])
def update_profile_pic():
    """
    Endpoint dedicado para a atualização da foto de perfil.
    É uma rota separada para maior granularidade e facilidade de uso do frontend.
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Não autenticado'}), 401

    if 'profile_pic' not in request.files:
        return jsonify({'error': 'Nenhum arquivo fornecido'}), 400

    file = request.files['profile_pic']
    if file.filename == '':
        return jsonify({'error': 'Nenhum arquivo selecionado'}), 400

    if file and allowed_file(file.filename):
        # Gera um nome de arquivo único para a nova foto
        filename = f"{session['user_id']}_{int(datetime.now().timestamp())}.{file.filename.rsplit('.', 1)[1].lower()}"
        filepath = os.path.join(app.config['PROFILE_PICS_FOLDER'], filename)
        file.save(filepath)

        # Remove a foto antiga do sistema de arquivos, se não for a padrão
        user = users_collection.find_one({'_id': ObjectId(session['user_id'])})
        if user and 'profile_pic' in user and user['profile_pic'] != 'user-icon-pequeno.png':
            old_pic_path = os.path.join(app.config['PROFILE_PICS_FOLDER'], user['profile_pic'])
            if os.path.exists(old_pic_path):
                os.remove(old_pic_path)

        # Atualiza o nome da foto de perfil no banco de dados do usuário
        users_collection.update_one(
            {'_id': ObjectId(session['user_id'])},
            {'$set': {'profile_pic': filename}}
        )

        return jsonify({'success': 'Foto de perfil atualizada!', 'filename': filename})

    return jsonify({'error': 'Tipo de arquivo não permitido'}), 400

@app.route('/api/update_company', methods=['POST'])
def update_company():
    """
    Endpoint para buscar e atualizar dados de empresa (CNPJ) através de uma API externa (Receita WS).
    Atualiza as coleções de usuários e empresas com os dados obtidos.
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Não autenticado'}), 401

    data = request.get_json()
    # Remove qualquer caractere que não seja dígito do CNPJ
    cnpj = re.sub(r'\D', '', data.get('cnpj', ''))

    if not cnpj or len(cnpj) != 14:
        return jsonify({'error': 'CNPJ inválido. Deve conter 14 dígitos.'}), 400

    try:
        # Realiza a requisição HTTP para a API da Receita WS
        response = requests.get(f'https://www.receitaws.com.br/v1/cnpj/{cnpj}')
        response.raise_for_status() # Lança um erro para status de erro HTTP (4xx ou 5xx)
        company_data = response.json()

        if company_data.get('status') == 'ERROR':
            return jsonify({'error': company_data.get('message', 'Erro ao consultar CNPJ na Receita WS.')}), 400
        if 'nome' not in company_data:
            return jsonify({'error': 'Não foi possível obter os dados completos do CNPJ.'}), 400

        # Atualiza o CNPJ no documento do usuário
        users_collection.update_one(
            {'_id': ObjectId(session['user_id'])},
            {'$set': {'cnpj': cnpj}}
        )

        # Atualiza ou cria a empresa na coleção `companies_collection`
        companies_collection.update_one(
            {'owner_id': session['user_id']}, # Associa ao user_id da sessão
            {'$set': {
                'cnpj': cnpj,
                'name': company_data.get('fantasia', company_data.get('nome', 'Empresa')), # Prefere fantasia, senão nome, senão "Empresa"
                'data': company_data, # Armazena todos os dados da API
                'updated_at': datetime.now()
            }},
            upsert=True # Se não encontrar, cria um novo documento
        )

        return jsonify({
            'success': 'Dados da empresa atualizados com sucesso!',
            'company': company_data
        })

    except requests.exceptions.RequestException as e:
        # Captura erros de requisição HTTP (conexão, timeout, etc.)
        return jsonify({'error': f'Erro de comunicação com a API da Receita WS: {str(e)}'}), 500
    except Exception as e:
        # Captura outros erros inesperados
        return jsonify({'error': f'Erro interno ao processar dados da empresa: {str(e)}'}), 500

# --- Execução da Aplicação ---
if __name__ == '__main__':
    # Cria as pastas de upload se elas não existirem
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['PROFILE_PICS_FOLDER'], exist_ok=True)
    # Em produção, você não usaria app.run(debug=True).
    # Em vez disso, usaria um servidor WSGI como Gunicorn.
    # Exemplo: gunicorn -w 4 -b 0.0.0.0:8000 app:app
    app.run(debug=False) # Mudei para False para simular ambiente de produção
