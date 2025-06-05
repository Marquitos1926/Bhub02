from flask import Flask, request, jsonify, redirect, url_for, render_template, session, send_from_directory
import re
import os
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta, datetime
from pymongo import MongoClient
from bson.objectid import ObjectId
from bson import json_util
import json
import requests

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

# Configurações
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['PROFILE_PICS_FOLDER'] = 'static/profile_pics'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)

# Conexão com MongoDB usando variável de ambiente
mongo_uri = os.environ.get('MONGODB_URI', "mongodb+srv://juliocardoso:z5fTsL8EAgD8SORa@dbbhub.nxcw2n9.mongodb.net/?retryWrites=true&w=majority")
client = MongoClient(mongo_uri)
db = client.get_database("dbbhub")

# Coleções
users_collection = db.users
cnpjs_collection = db.cnpjs
posts_collection = db.posts
companies_collection = db.companies

# --- Funções Auxiliares ---
def validate_username(username):
    pattern = r'^[a-zA-Z0-9_.-]+$'
    if not re.match(pattern, username):
        return False, "Nome de usuário inválido", "Pode conter apenas letras, números, pontos, traços e underscores."
    if len(username) < 4:
        return False, "Nome muito curto", "Deve ter pelo menos 4 caracteres."
    if len(username) > 20:
        return False, "Nome muito longo", "Deve ter no máximo 20 caracteres."
    return True, "", ""

def validate_email(email):
    pattern = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
    if not re.match(pattern, email):
        return False, "Email inválido", "Por favor, insira um e-mail válido."
    return True, "", ""

def validate_password(password):
    if len(password) < 8:
        return False, "Senha muito curta", "A senha deve ter no mínimo 8 caracteres."
    return True, "", ""

def validate_phone(phone):
    phone = ''.join(filter(str.isdigit, phone))
    if len(phone) < 10 or len(phone) > 11:
        return False, "Telefone inválido", "Use DDD + número (10 ou 11 dígitos)."
    return True, "", ""

def validate_cnpj(cnpj):
    cnpj = ''.join(filter(str.isdigit, cnpj))
    if len(cnpj) != 14:
        return False, "CNPJ inválido", "O CNPJ deve conter 14 dígitos."
    return True, "", ""

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def get_user_data(username):
    user = users_collection.find_one({'username': username})
    if user:
        user['_id'] = str(user['_id'])
        if 'profile_pic' not in user or not user['profile_pic']:
            user['profile_pic'] = 'user-icon-pequeno.png'
    return user

# --- Rotas Principais ---
@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('index'))
    return redirect(url_for('login'))

@app.route('/index')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = get_user_data(session['username'])
    if not user:
        session.clear()
        return redirect(url_for('login'))

    posts = list(posts_collection.find().sort('created_at', -1).limit(10))
    
    for post in posts:
        post['_id'] = str(post['_id'])
        post['author_id'] = str(post['author_id'])
        author_user = users_collection.find_one({'_id': ObjectId(post['author_id'])})
        post['author_profile_pic'] = author_user['profile_pic'] if author_user and 'profile_pic' in author_user and author_user['profile_pic'] else 'user-icon-pequeno.png'

    return render_template('index.html', username=session['username'], user=user, posts=posts)

@app.route('/explore')
def explore():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = get_user_data(session['username'])
    if not user:
        session.clear()
        return redirect(url_for('login'))

    companies = list(companies_collection.find().limit(20))
    for company in companies:
        company['_id'] = str(company['_id'])

    all_users = list(users_collection.find({}, {'username': 1, 'profile_pic': 1}))
    for u in all_users:
        u['_id'] = str(u['_id'])
        u['profile_pic'] = u.get('profile_pic', 'user-icon-pequeno.png')

    return render_template('explore.html', username=session['username'], user=user, companies=companies, all_users=all_users)

# --- Rotas de API ---
@app.route('/api/companies')
def api_companies():
    if 'username' not in session:
        return jsonify({'error': 'Não autenticado'}), 401

    companies = list(companies_collection.find({}, {'name': 1, 'description': 1, 'logo': 1}))
    for company in companies:
        company['_id'] = str(company['_id'])

    return json.loads(json_util.dumps(companies))

@app.route('/api/posts')
def api_posts():
    if 'username' not in session:
        return jsonify({'error': 'Não autenticado'}), 401

    posts = list(posts_collection.find().sort('created_at', -1).limit(10))
    for post in posts:
        post['_id'] = str(post['_id'])
        post['author_id'] = str(post['author_id'])
        author_user = users_collection.find_one({'_id': ObjectId(post['author_id'])})
        post['author_profile_pic'] = author_user['profile_pic'] if author_user and 'profile_pic' in author_user and author_user['profile_pic'] else 'user-icon-pequeno.png'

    return json.loads(json_util.dumps(posts))

@app.route('/api/create_post', methods=['POST'])
def create_post():
    if 'username' not in session:
        return jsonify({'error': 'Não autenticado'}), 401

    content = request.form.get('content')
    user_id = session.get('user_id')
    username = session.get('username')

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

    if 'image' in request.files:
        file = request.files['image']
        if file and allowed_file(file.filename):
            filename = f"{session['user_id']}_{int(datetime.now().timestamp())}.{file.filename.rsplit('.', 1)[1].lower()}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            post_data['image'] = filename

    posts_collection.insert_one(post_data)
    return jsonify({'success': 'Post criado com sucesso!'})

@app.route('/api/like_post/<post_id>', methods=['POST'])
def like_post(post_id):
    if 'username' not in session:
        return jsonify({'error': 'Não autenticado'}), 401

    user_id = session['user_id']

    try:
        post = posts_collection.find_one({'_id': ObjectId(post_id)})
        if not post:
            return jsonify({'error': 'Post não encontrado.'}), 404

        if user_id in post.get('likes', []):
            posts_collection.update_one(
                {'_id': ObjectId(post_id)},
                {'$pull': {'likes': user_id}}
            )
            return jsonify({'success': 'Curtida removida.'})
        else:
            posts_collection.update_one(
                {'_id': ObjectId(post_id)},
                {'$push': {'likes': user_id}}
            )
            return jsonify({'success': 'Post curtido!'})
    except Exception as e:
        return jsonify({'error': f'Erro ao processar like: {str(e)}'}), 500

# --- Autenticação ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('rememberMe') == 'on'

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

        session['username'] = username
        session['user_id'] = str(user['_id'])
        if remember:
            session.permanent = True

        return jsonify({
            'status': 'success',
            'title': 'Login bem-sucedido',
            'message': 'Você será redirecionado...',
            'redirect': url_for('index')
        })

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('newUsername')
        password = request.form.get('newPassword')
        email = request.form.get('email')
        phone = request.form.get('phone')
        cnpj = request.form.get('cnpj')

        if not all([username, password, email]):
            return jsonify({
                'status': 'error',
                'title': 'Campos obrigatórios',
                'message': 'Preencha todos os campos obrigatórios.'
            }), 400

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

        is_valid, title, message = validate_password(password)
        if not is_valid:
            return jsonify({
                'status': 'error',
                'title': title,
                'message': message
            }), 400

        if cnpj and cnpj.strip():
            formatted_cnpj = ''.join(filter(str.isdigit, cnpj))
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

            cnpjs_collection.insert_one({'cnpj': formatted_cnpj})
        else:
            formatted_cnpj = None

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
            formatted_phone = None

        user_data = {
            'username': username,
            'password': generate_password_hash(password),
            'email': email,
            'phone': formatted_phone,
            'cnpj': formatted_cnpj,
            'created_at': datetime.now(),
            'consent_given': False,
            'profile_pic': 'user-icon-pequeno.png'
        }

        result = users_collection.insert_one(user_data)

        if formatted_cnpj:
            company_data = {
                'name': username,
                'cnpj': formatted_cnpj,
                'description': f'Empresa de {username} no BusinessHub',
                'logo': 'company-default.png',
                'owner_id': str(result.inserted_id),
                'created_at': datetime.now()
            }
            companies_collection.insert_one(company_data)

        return jsonify({
            'status': 'success',
            'title': 'Cadastro realizado!',
            'message': 'Seu cadastro foi concluído com sucesso.',
            'redirect': url_for('login')
        })

    return render_template('login.html')

@app.route('/consent', methods=['POST'])
def consent():
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
            session['consent_given'] = True
        return jsonify({'success': 'Consentimento registrado.'})
    return jsonify({'error': 'Aceite todos os termos para continuar.'}), 400

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# --- Perfil ---
@app.route('/perfil')
def show_profile():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = get_user_data(session['username'])
    if not user:
        session.clear()
        return redirect(url_for('login'))

    company = None
    if 'cnpj' in user and user['cnpj']:
        company = companies_collection.find_one({'owner_id': user['_id']})
        if company:
            company['_id'] = str(company['_id'])

    return render_template('perfil.html', user=user, company=company)

@app.route('/api/update_profile', methods=['POST'])
def update_profile():
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

    if new_username and new_username != current_user_doc.get('username'):
        is_valid, title, message = validate_username(new_username)
        if not is_valid:
            return jsonify({'status': 'error', 'message': f"{title}: {message}"}), 400
        if users_collection.find_one({'username': new_username, '_id': {'$ne': ObjectId(user_id)}}):
            return jsonify({'status': 'error', 'message': 'Este nome de usuário já está em uso.'}), 400
        update_data['username'] = new_username
        session['username'] = new_username

    if new_email and new_email != current_user_doc.get('email'):
        is_valid, title, message = validate_email(new_email)
        if not is_valid:
            return jsonify({'status': 'error', 'message': f"{title}: {message}"}), 400
        if users_collection.find_one({'email': new_email, '_id': {'$ne': ObjectId(user_id)}}):
            return jsonify({'status': 'error', 'message': 'Este e-mail já está cadastrado.'}), 400
        update_data['email'] = new_email

    processed_new_cnpj = ''.join(filter(str.isdigit, new_cnpj)) if new_cnpj else None
    current_cnpj = current_user_doc.get('cnpj')

    if processed_new_cnpj != current_cnpj:
        if processed_new_cnpj:
            is_valid, title, message = validate_cnpj(processed_new_cnpj)
            if not is_valid:
                return jsonify({'status': 'error', 'message': f"{title}: {message}"}), 400
            if cnpjs_collection.find_one({'cnpj': processed_new_cnpj, 'user_id': {'$ne': ObjectId(user_id)} if user_id else {'$exists': False}}):
                return jsonify({'status': 'error', 'message': 'Este CNPJ já está cadastrado para outro usuário.'}), 400

            update_data['cnpj'] = processed_new_cnpj
            cnpjs_collection.update_one(
                {'user_id': ObjectId(user_id)},
                {'$set': {'cnpj': processed_new_cnpj, 'user_id': ObjectId(user_id)}},
                upsert=True
            )
            companies_collection.update_one(
                {'owner_id': user_id},
                {'$set': {
                    'cnpj': processed_new_cnpj,
                    'name': current_user_doc.get('username', 'Empresa'),
                    'updated_at': datetime.now()
                }},
                upsert=True
            )
        else:
            update_data['cnpj'] = None
            cnpjs_collection.delete_one({'user_id': ObjectId(user_id)})
            companies_collection.delete_one({'owner_id': user_id})

    processed_new_phone = ''.join(filter(str.isdigit, new_phone)) if new_phone else None
    current_phone = current_user_doc.get('phone')

    if processed_new_phone != current_phone:
        if processed_new_phone:
            is_valid, title, message = validate_phone(processed_new_phone)
            if not is_valid:
                return jsonify({'status': 'error', 'message': f"{title}: {message}"}), 400
            update_data['phone'] = processed_new_phone
        else:
            update_data['phone'] = None

    if 'profile_pic' in request.files:
        file = request.files['profile_pic']
        if file.filename != '' and allowed_file(file.filename):
            filename = f"{user_id}_{int(datetime.now().timestamp())}.{file.filename.rsplit('.', 1)[1].lower()}"
            filepath = os.path.join(app.config['PROFILE_PICS_FOLDER'], filename)
            file.save(filepath)
            update_data['profile_pic'] = filename

            old_pic = current_user_doc.get('profile_pic')
            if old_pic and old_pic != 'user-icon-pequeno.png' and \
               os.path.exists(os.path.join(app.config['PROFILE_PICS_FOLDER'], old_pic)):
                os.remove(os.path.join(app.config['PROFILE_PICS_FOLDER'], old_pic))
        elif file.filename == '' and current_user_doc.get('profile_pic') != 'user-icon-pequeno.png':
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

# --- Recuperação de Senha ---
@app.route('/recuperar_senha')
def show_recover_password():
    return render_template('recuperar_senha.html')

@app.route('/recover_password', methods=['POST'])
def recover_password():
    identifier = request.form.get('recoveryIdentifier')
    user = users_collection.find_one({'$or': [{'email': identifier}, {'username': identifier}]})

    if user:
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

# --- Arquivos Estáticos ---
@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

# --- API Auxiliares ---
@app.route('/api/check-auth')
def check_auth():
    return jsonify({
        'authenticated': 'username' in session,
        'username': session.get('username', '')
    })

@app.route('/api/update_profile_pic', methods=['POST'])
def update_profile_pic():
    if 'user_id' not in session:
        return jsonify({'error': 'Não autenticado'}), 401

    if 'profile_pic' not in request.files:
        return jsonify({'error': 'Nenhum arquivo fornecido'}), 400

    file = request.files['profile_pic']
    if file.filename == '':
        return jsonify({'error': 'Nenhum arquivo selecionado'}), 400

    if file and allowed_file(file.filename):
        filename = f"{session['user_id']}_{int(datetime.now().timestamp())}.{file.filename.rsplit('.', 1)[1].lower()}"
        filepath = os.path.join(app.config['PROFILE_PICS_FOLDER'], filename)
        file.save(filepath)

        user = users_collection.find_one({'_id': ObjectId(session['user_id'])})
        if user and 'profile_pic' in user and user['profile_pic'] != 'user-icon-pequeno.png':
            old_pic_path = os.path.join(app.config['PROFILE_PICS_FOLDER'], user['profile_pic'])
            if os.path.exists(old_pic_path):
                os.remove(old_pic_path)

        users_collection.update_one(
            {'_id': ObjectId(session['user_id'])},
            {'$set': {'profile_pic': filename}}
        )

        return jsonify({'success': 'Foto de perfil atualizada!', 'filename': filename})

    return jsonify({'error': 'Tipo de arquivo não permitido'}), 400

@app.route('/api/update_company', methods=['POST'])
def update_company():
    if 'user_id' not in session:
        return jsonify({'error': 'Não autenticado'}), 401

    data = request.get_json()
    cnpj = re.sub(r'\D', '', data.get('cnpj', ''))

    if not cnpj or len(cnpj) != 14:
        return jsonify({'error': 'CNPJ inválido. Deve conter 14 dígitos.'}), 400

    try:
        response = requests.get(f'https://www.receitaws.com.br/v1/cnpj/{cnpj}')
        response.raise_for_status()
        company_data = response.json()

        if company_data.get('status') == 'ERROR':
            return jsonify({'error': company_data.get('message', 'Erro ao consultar CNPJ na Receita WS.')}), 400
        if 'nome' not in company_data:
            return jsonify({'error': 'Não foi possível obter os dados completos do CNPJ.'}), 400

        users_collection.update_one(
            {'_id': ObjectId(session['user_id'])},
            {'$set': {'cnpj': cnpj}}
        )

        companies_collection.update_one(
            {'owner_id': session['user_id']},
            {'$set': {
                'cnpj': cnpj,
                'name': company_data.get('fantasia', company_data.get('nome', 'Empresa')),
                'data': company_data,
                'updated_at': datetime.now()
            }},
            upsert=True
        )

        return jsonify({
            'success': 'Dados da empresa atualizados com sucesso!',
            'company': company_data
        })

    except requests.exceptions.RequestException as e:
        return jsonify({'error': f'Erro de comunicação com a API da Receita WS: {str(e)}'}), 500
    except Exception as e:
        return jsonify({'error': f'Erro interno ao processar dados da empresa: {str(e)}'}), 500

# --- Inicialização ---
if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['PROFILE_PICS_FOLDER'], exist_ok=True)
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
