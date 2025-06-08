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
import random

# A linha abaixo está OK, o Flask já procura por 'templates' por padrão
# mas explicitá-la não causa erro se a pasta estiver no lugar certo.
app = Flask(__name__, template_folder='templates')

# --- Configurações da Aplicação ---
# Em produção, a chave secreta deve ser carregada de uma variável de ambiente.
# Isso garante que a chave é persistente e segura.
app.secret_key = os.environ.get('FLASK_SECRET_KEY', os.urandom(24))

# Define os caminhos absolutos para as pastas de upload
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'static', 'uploads') # Pasta para uploads de posts
app.config['PROFILE_PICS_FOLDER'] = os.path.join(BASE_DIR, 'static', 'profile_pics') # Pasta para fotos de perfil
app.config['IMAGES_FOLDER'] = os.path.join(BASE_DIR, 'static', 'images') # Adicionar pasta para imagens de empresas/posts (se aplicável)
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'} # Extensões de arquivo permitidas

# --- Conexão com MongoDB ---
# É uma boa prática armazenar a URI em uma variável de ambiente para produção.
# AQUI ESTÁ A LINHA CORRIGIDA:
# O primeiro argumento é o NOME da variável de ambiente ("MONGO_URI").
# O segundo argumento é o VALOR DEFAULT (sua URI de conexão completa com a senha REAL).
mongo_uri = os.environ.get("MONGO_URI", "mongodb+srv://juliocardoso:1XIo2RrBrHSMZEIl@bd-bhub.pmuu5go.mongodb.net/?retryWrites=true&w=majority&appName=BD-BHUB")
client = MongoClient(mongo_uri)
db = client.get_database("dbbhub")

# --- Coleções do Banco de Dados ---
users_collection = db.users
cnpjs_collection = db.cnpjs # Usado para controle de CNPJs já cadastrados e associados a user_id
posts_collection = db.posts
companies_collection = db.companies # Armazena informações detalhadas da empresa consultada via Receita WS
conversations_collection = db.conversations # Nova coleção para conversas
connection_requests_collection = db.connection_requests # Nova coleção para solicitações de conexão

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
        # Garante que 'consent_given' existe, mesmo que seja False por padrão
        user['consent_given'] = user.get('consent_given', False)
    return user

# --- Rotas Principais da Aplicação ---
@app.route('/')
def home():
    """
    Renderiza a página inicial (index.html).
    Se o usuário estiver logado E consentiu, redireciona para o dashboard.
    Caso contrário, exibe o index.html.
    """
    if 'username' in session and 'user_id' in session and session.get('consent_given', False):
        return redirect(url_for('dashboard'))
    return render_template('index.html') # A nova página inicial


@app.route('/test-server')
def test_server():
    """Uma rota simples para verificar se o servidor está funcionando."""
    return "Servidor Flask está funcionando! 🎉"

@app.route('/dashboard')
def dashboard():
    """
    Renderiza a página principal (feed de posts) se o usuário estiver autenticado E consentiu.
    Caso contrário, redireciona para a página de login para forçar o consentimento.
    """
    # É fundamental que esta verificação aconteça ANTES de tentar renderizar o template
    if 'username' not in session or 'user_id' not in session:
        return redirect(url_for('login'))

    # Verifica o status do consentimento na sessão.
    # A sessão é atualizada no login e na API de consentimento.
    if not session.get('consent_given', False):
        return redirect(url_for('login', require_consent=True))

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
        # Adicione o username do autor ao post
        post['author_username'] = author_user['username'] if author_user else 'Usuário Desconhecido'

    return render_template('Dashboard.html',
                           username=session['username'],
                           user=user,
                           posts=posts)

@app.route('/explore')
def explore():
    """
    Renderiza a página de exploração, exibindo posts (de empresas) e outros usuários.
    Requer autenticação E consentimento.
    """
    if 'username' not in session or 'user_id' not in session:
        return redirect(url_for('login'))

    # Verifica o status do consentimento na sessão
    if not session.get('consent_given', False):
        return redirect(url_for('login', require_consent=True))

    user = get_user_data(session['username'])
    if not user:
        session.clear()
        return redirect(url_for('login'))


    # Buscar todas as empresas/posts para a seção principal de exploração
    companies_posts = list(posts_collection.find().sort('created_at', -1).limit(20)) # Buscar posts mais recentes
    for post in companies_posts:
        post['_id'] = str(post['_id'])
        post['author_id'] = str(post['author_id'])

        # Obter informações do autor do post
        author_user = users_collection.find_one({'_id': ObjectId(post['author_id'])})
        if author_user:
            post['author_name'] = author_user.get('username', 'Usuário Desconhecido')
            post['author_profile_pic'] = author_user.get('profile_pic', 'user-icon-pequeno.png')
        else:
            post['author_name'] = 'Usuário Desconhecido'
            post['author_profile_pic'] = 'user-icon-pequeno.png'

        # Para posts, podemos querer likes e comentários. Assumindo que você tem 'likes' e 'comments' como arrays de user_ids.
        post['likes_count'] = len(post.get('likes', []))
        post['comments_count'] = len(post.get('comments', []))

        # Ajusta o caminho da imagem do post
        if 'image' in post and post['image']:
            # Usar url_for para gerar o caminho correto
            post['display_image'] = url_for('static_uploads', filename=post['image'])
        else:
            post['display_image'] = url_for('static', filename='company-default.png') # Imagem padrão se não houver

    # Buscar todos os usuários para a sidebar (simulando status online/offline)
    all_users = list(users_collection.find({}, {'username': 1, 'profile_pic': 1}))
    for u in all_users:
        u['_id'] = str(u['_id'])
        if 'profile_pic' not in u or not u['profile_pic']:
            u['profile_pic'] = 'user-icon-pequeno.png'
        # Simula status online/offline para cada usuário
        u['status'] = 'online' if random.random() > 0.5 else 'offline' # 50% de chance de ser online

    return render_template('explore.html',
                           username=session['username'],
                           user=user,
                           companies=companies_posts, # Passando os posts para a seção de empresas
                           all_users=all_users)

# --- Nova Rota para a Área de Mensagens ---
@app.route('/messages')
def messages():
    """
    Renderiza a página de mensagens.
    Requer autenticação E consentimento.
    """
    if 'username' not in session or 'user_id' not in session:
        return redirect(url_for('login'))

    # Verifica o status do consentimento na sessão
    if not session.get('consent_given', False):
        return redirect(url_for('login', require_consent=True))

    user = get_user_data(session['username'])
    if not user:
        session.clear()
        return redirect(url_for('login'))

    current_user_id = user['_id']

    # Buscar todas as conversas do usuário logado
    # Uma conversa envolve o current_user_id e um ou mais outros participantes
    # Para simplicidade, vamos considerar conversas entre 2 usuários por enquanto
    conversations = list(conversations_collection.find({
        'participants': current_user_id   # Busca conversas onde o current_user_id é um dos participantes
    }).sort('last_message_at', -1)) # Ordena pela última mensagem

    formatted_conversations = []
    for convo in conversations:
        convo['_id'] = str(convo['_id'])

        # Encontrar o outro participante
        other_participant_id = None
        for p_id in convo['participants']:
            if p_id != current_user_id:
                other_participant_id = p_id
                break

        # Se other_participant_id for None (conversa de grupo que não está sendo tratada, ou erro)
        if not other_participant_id:
            continue # Pula esta conversa se não encontrar outro participante em uma conversa a dois

        other_user_info = users_collection.find_one({'_id': ObjectId(other_participant_id)}, {'username': 1, 'profile_pic': 1})
        if other_user_info:
            other_user_info['_id'] = str(other_user_info['_id']) # Garante que o ID do outro user é string
            if 'profile_pic' not in other_user_info or not other_user_info['profile_pic']:
                other_user_info['profile_pic'] = 'user-icon-pequeno.png'

            convo['other_participant'] = other_user_info

            # Formata a última mensagem para exibição na lista de conversas
            if convo.get('messages'):
                convo['last_message_content'] = convo['messages'][-1]['content']
                convo['last_message_time'] = convo['messages'][-1]['timestamp'].strftime('%H:%M')
            else:
                convo['last_message_content'] = 'Nenhuma mensagem'
                convo['last_message_time'] = ''

            formatted_conversations.append(convo)
        else:
            # Caso o outro usuário não seja encontrado (ex: deletado), ainda mostre a conversa
            convo['other_participant'] = {'username': 'Usuário Desconhecido', 'profile_pic': 'user-icon-pequeno.png', '_id': None}
            if convo.get('messages'):
                convo['last_message_content'] = convo['messages'][-1]['content']
                convo['last_message_time'] = convo['messages'][-1]['timestamp'].strftime('%H:%M')
            else:
                convo['last_message_content'] = 'Nenhuma mensagem'
                convo['last_message_time'] = ''
            formatted_conversations.append(convo)


    # Buscar solicitações de conexão pendentes para o usuário logado
    pending_requests = list(connection_requests_collection.find({
        'receiver_id': current_user_id,
        'status': 'pending'
    }))

    formatted_pending_requests = []
    for req in pending_requests:
        req['_id'] = str(req['_id'])
        sender_info = users_collection.find_one({'_id': ObjectId(req['sender_id'])}, {'username': 1, 'profile_pic': 1})
        if sender_info:
            sender_info['_id'] = str(sender_info['_id'])
            if 'profile_pic' not in sender_info or not sender_info['profile_pic']:
                sender_info['profile_pic'] = 'user-icon-pequeno.png'
            req['sender_info'] = sender_info
            formatted_pending_requests.append(req)

    return render_template('messages.html',
                           user=user,
                           conversations=formatted_conversations,
                           pending_requests=formatted_pending_requests)

# --- Adicione esta nova rota para servir arquivos da pasta 'uploads'
@app.route('/static/uploads/<filename>')
def static_uploads(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# --- Endpoints da API ---
@app.route('/api/companies')
def api_companies():
    """
    Endpoint para retornar uma lista de empresas em formato JSON.
    Requer autenticação e consentimento.
    """
    if 'username' not in session or 'user_id' not in session:
        return jsonify({'error': 'Não autenticado'}), 401

    # Verifica o status do consentimento na sessão
    if not session.get('consent_given', False):
        return jsonify({'error': 'Consentimento necessário'}), 403

    companies = list(companies_collection.find({}, {'name': 1, 'description': 1, 'logo': 1}))
    for company in companies:
        company['_id'] = str(company['_id'])

    # Usa json_util.dumps para lidar com ObjectIds do MongoDB e depois carrega como JSON normal
    return json.loads(json_util.dumps(companies))

@app.route('/api/posts')
def api_posts():
    """
    Endpoint para retornar uma lista de posts em formato JSON.
    Requer autenticação e consentimento.
    """
    if 'username' not in session or 'user_id' not in session:
        return jsonify({'error': 'Não autenticado'}), 401

    # Verifica o status do consentimento na sessão
    if not session.get('consent_given', False):
        return jsonify({'error': 'Consentimento necessário'}), 403

    posts = list(posts_collection.find().sort('created_at', -1).limit(10))
    for post in posts:
        post['_id'] = str(post['_id'])
        post['author_id'] = str(post['author_id'])

        author_user = users_collection.find_one({'_id': ObjectId(post['author_id'])})
        if author_user and 'profile_pic' in author_user and author_user['profile_pic']:
            post['author_profile_pic'] = author_user['profile_pic']
        else:
            post['author_profile_pic'] = 'user-icon-pequeno.png'
        post['author_username'] = author_user['username'] if author_user else 'Usuário Desconhecido'

    return json.loads(json_util.dumps(posts))

@app.route('/api/create_post', methods=['POST'])
def create_post():
    """
    Endpoint para criar um novo post.
    Permite conteúdo de texto e/ou imagem.
    Requer autenticação e consentimento.
    """
    if 'username' not in session or 'user_id' not in session:
        return jsonify({'error': 'Não autenticado'}), 401

    # Verifica o status do consentimento na sessão
    if not session.get('consent_given', False):
        return jsonify({'error': 'Consentimento necessário'}), 403


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
    Requer autenticação e consentimento.
    """
    if 'username' not in session or 'user_id' not in session:
        return jsonify({'error': 'Não autenticado'}), 401

    # Verifica o status do consentimento na sessão
    if not session.get('consent_given', False):
        return jsonify({'error': 'Consentimento necessário'}), 403

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

@app.route('/api/conversations/<conversation_id>')
def get_conversation_messages(conversation_id):
    """
    Endpoint para buscar as mensagens de uma conversa específica.
    Requer autenticação e que o usuário seja participante da conversa E consentimento.
    """
    if 'username' not in session or 'user_id' not in session:
        return jsonify({'error': 'Não autenticado'}), 401

    # Verifica o status do consentimento na sessão
    if not session.get('consent_given', False):
        return jsonify({'error': 'Consentimento necessário'}), 403

    current_user_id = session['user_id']

    # Busca a conversa
    conversation = conversations_collection.find_one({'_id': ObjectId(conversation_id)})
    if not conversation:
        return jsonify({'error': 'Conversa não encontrada.'}), 404

    # Verifica se o usuário logado é participante da conversa
    if current_user_id not in conversation['participants']:
        return jsonify({'error': 'Você não tem permissão para acessar esta conversa.'}), 403

    # Prepara as mensagens
    messages = conversation.get('messages', [])
    for msg in messages:
        msg['_id'] = str(msg['_id']) # Garante que o ID da mensagem é string
        # Formata a data e hora para exibição
        msg['timestamp_formatted'] = msg['timestamp'].strftime('%d/%m/%Y %H:%M')

    return json.loads(json_util.dumps(messages))


@app.route('/api/send_message', methods=['POST'])
def send_message():
    """
    Endpoint para enviar uma nova mensagem.
    Cria uma nova conversa se não existir, ou adiciona à conversa existente.
    Requer autenticação e consentimento.
    """
    if 'username' not in session or 'user_id' not in session:
        return jsonify({'error': 'Não autenticado'}), 401

    # Verifica o status do consentimento na sessão
    if not session.get('consent_given', False):
        return jsonify({'error': 'Consentimento necessário'}), 403

    data = request.get_json()
    receiver_id = data.get('receiver_id')
    message_content = data.get('message_content')

    if not receiver_id or not message_content:
        return jsonify({'error': 'Destinatário e conteúdo da mensagem são necessários.'}), 400

    sender_id = session['user_id']

    # Verifique se o receiver_id é um ID válido
    try:
        receiver_obj_id = ObjectId(receiver_id)
        receiver_user = users_collection.find_one({'_id': receiver_obj_id})
        if not receiver_user:
            return jsonify({'error': 'Destinatário não encontrado.'}), 404
    except Exception:
        return jsonify({'error': 'ID de destinatário inválido.'}), 400

    # Tenta encontrar uma conversa existente entre os dois usuários
    # A ordem dos participantes não importa para a busca: use $all
    # Importante: Os IDs no array 'participants' devem ser strings para comparação com sender_id/receiver_id (que são strings)
    conversation = conversations_collection.find_one({
        'participants': { '$all': [sender_id, receiver_id] },
        'is_group': False # Considera apenas conversas individuais
    })

    new_message = {
        '_id': ObjectId(), # Gera um ObjectId único para a mensagem
        'sender_id': sender_id,
        'content': message_content,
        'timestamp': datetime.now()
    }

    if conversation:
        # Adiciona a nova mensagem à conversa existente
        conversations_collection.update_one(
            {'_id': conversation['_id']},
            {
                '$push': {'messages': new_message},
                '$set': {'last_message_at': datetime.now()}
            }
        )
        conversation_id = str(conversation['_id'])
    else:
        # Cria uma nova conversa
        # O sender_id e receiver_id já são strings aqui
        new_conversation = {
            'participants': [sender_id, receiver_id],
            'messages': [new_message],
            'created_at': datetime.now(),
            'last_message_at': datetime.now(),
            'is_group': False   # Marca como conversa individual
        }
        result = conversations_collection.insert_one(new_conversation)
        conversation_id = str(result.inserted_id)

    return jsonify({
        'success': 'Mensagem enviada com sucesso!',
        'conversation_id': conversation_id,
        'message_id': str(new_message['_id']),
        'timestamp': new_message['timestamp'].isoformat()
    })


@app.route('/api/send_connection_request', methods=['POST'])
def send_connection_request():
    """
    Endpoint para enviar uma solicitação de conexão a outro usuário.
    Requer autenticação e consentimento.
    """
    if 'username' not in session or 'user_id' not in session:
        return jsonify({'error': 'Não autenticado'}), 401

    # Verifica o status do consentimento na sessão
    if not session.get('consent_given', False):
        return jsonify({'error': 'Consentimento necessário'}), 403

    data = request.get_json()
    receiver_id = data.get('receiver_id')

    if not receiver_id:
        return jsonify({'error': 'ID do destinatário é necessário.'}), 400

    sender_id = session['user_id']

    if sender_id == receiver_id:
        return jsonify({'error': 'Você não pode enviar uma solicitação de conexão para si mesmo.'}), 400

    # Verifica se já existe uma solicitação pendente ou aceita
    existing_request = connection_requests_collection.find_one({
        '$or': [
            {'sender_id': sender_id, 'receiver_id': receiver_id}, # Solicitacao que eu ja enviei
            {'sender_id': receiver_id, 'receiver_id': sender_id}   # Solicitacao que o outro usuario me enviou
        ]
    })

    if existing_request:
        if existing_request['status'] == 'pending':
            if existing_request['sender_id'] == sender_id:
                return jsonify({'error': 'Você já enviou uma solicitação para este usuário.'}), 400
            else: # existing_request['sender_id'] == receiver_id (o outro me enviou)
                return jsonify({'error': 'Este usuário já enviou uma solicitação para você. Por favor, aceite-a na área de solicitações.'}), 400
        elif existing_request['status'] == 'accepted':
            return jsonify({'error': 'Vocês já estão conectados.'}), 400

    # Verifica se o receiver_id é um ID de usuário válido
    receiver_user = users_collection.find_one({'_id': ObjectId(receiver_id)})
    if not receiver_user:
        return jsonify({'error': 'Usuário destinatário não encontrado.'}), 404

    request_data = {
        'sender_id': sender_id,
        'receiver_id': receiver_id,
        'status': 'pending',     # status: pending, accepted, rejected
        'sent_at': datetime.now()
    }
    connection_requests_collection.insert_one(request_data)

    return jsonify({'success': 'Solicitação de conexão enviada com sucesso!'})


@app.route('/api/respond_connection_request', methods=['POST'])
def respond_connection_request():
    """
    Endpoint para responder a uma solicitação de conexão (aceitar ou rejeitar).
    Requer autenticação e consentimento.
    """
    if 'username' not in session or 'user_id' not in session:
        return jsonify({'error': 'Não autenticado'}), 401

    # Verifica o status do consentimento na sessão
    if not session.get('consent_given', False):
        return jsonify({'error': 'Consentimento necessário'}), 403

    data = request.get_json()
    request_id = data.get('request_id')
    action = data.get('action') # 'accept' or 'reject'

    if not request_id or action not in ['accept', 'reject']:
        return jsonify({'error': 'ID da solicitação e ação (accept/reject) são necessários.'}), 400

    current_user_id = session['user_id']

    connection_request = connection_requests_collection.find_one({'_id': ObjectId(request_id)})

    if not connection_request:
        return jsonify({'error': 'Solicitação não encontrada.'}), 404

    if connection_request['receiver_id'] != current_user_id:
        return jsonify({'error': 'Você não tem permissão para responder a esta solicitação.'}), 403

    if connection_request['status'] != 'pending':
        return jsonify({'error': 'Esta solicitação já foi respondida.'}), 400

    if action == 'accept':
        connection_requests_collection.update_one(
            {'_id': ObjectId(request_id)},
            {'$set': {'status': 'accepted', 'responded_at': datetime.now()}}
        )
        # Opcional: Criar uma conversa vazia assim que a conexão é aceita, se não existir
        # Isso facilita o início do chat. Note que 'upsert=True' no update_one fará isso.
        conversations_collection.update_one(
            {
                'participants': { '$all': [connection_request['sender_id'], connection_request['receiver_id']] },
                'is_group': False
            },
            {'$set': {
                'participants': [connection_request['sender_id'], connection_request['receiver_id']], # IDs são strings aqui
                'created_at': datetime.now(),
                'messages': [], # Inicia com mensagens vazias
                'last_message_at': datetime.now(), # Inicializa last_message_at
                'is_group': False
            }},
            upsert=True
        )
        return jsonify({'success': 'Solicitação de conexão aceita!'})
    elif action == 'reject':
        connection_requests_collection.update_one(
            {'_id': ObjectId(request_id)},
            {'$set': {'status': 'rejected', 'responded_at': datetime.now()}}
        )
        return jsonify({'success': 'Solicitação de conexão rejeitada.'})


@app.route('/api/search_users', methods=['GET'])
def search_users():
    """
    Endpoint para buscar usuários por nome de usuário.
    Retorna o status da conexão com o usuário logado.
    Requer autenticação e consentimento.
    """
    if 'username' not in session or 'user_id' not in session:
        return jsonify({'error': 'Não autenticado'}), 401

    # Verifica o status do consentimento na sessão
    if not session.get('consent_given', False):
        return jsonify({'error': 'Consentimento necessário'}), 403

    query = request.args.get('q', '').strip()
    if not query:
        return jsonify([])

    current_user_id = session['user_id']
    users = list(users_collection.find(
        {
            'username': {'$regex': query, '$options': 'i'}, # Case-insensitive regex search
            '_id': {'$ne': ObjectId(current_user_id)} # Exclui o próprio usuário
        },
        {'username': 1, 'profile_pic': 1}
    ).limit(10)) # Limita para não sobrecarregar

    for u in users:
        u['_id'] = str(u['_id'])
        if 'profile_pic' not in u or not u['profile_pic']:
            u['profile_pic'] = 'user-icon-pequeno.png'

        # Verifica o status da conexão
        existing_connection = connection_requests_collection.find_one({
            '$or': [
                {'sender_id': current_user_id, 'receiver_id': u['_id']},
                {'sender_id': u['_id'], 'receiver_id': current_user_id}
            ]
        })

        if existing_connection:
            u['connection_status'] = existing_connection['status']
            # Se a solicitação foi enviada pelo usuário logado, adicione uma flag
            if existing_connection['sender_id'] == current_user_id and existing_connection['status'] == 'pending':
                u['pending_sent_by_me'] = True
            u['request_id'] = str(existing_connection['_id']) # Passa o ID da solicitação para aceitar/rejeitar

        else:
            u['connection_status'] = 'none' # Nenhum status de conexão

    return json.loads(json_util.dumps(users))

# --- Rotas de Autenticação ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Lida com o login de usuários.
    GET: Exibe a página de login (que pode exibir o modal de consentimento).
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
        # AQUI: A sessão é atualizada com o status de consentimento do DB.
        session['consent_given'] = user.get('consent_given', False)

        if remember:
            session.permanent = True
            app.permanent_session_lifetime = timedelta(days=30) # Sessão permanente por 30 dias

        # Se o consentimento NÃO foi dado, redireciona para a própria página de login com o parâmetro
        if not session['consent_given']:
            return jsonify({
                'status': 'consent_required',
                'title': 'Termos de Uso',
                'message': 'Por favor, aceite nossos Termos de Uso e Política de Privacidade para acessar a plataforma.',
                'redirect': url_for('login', require_consent=True)
            })
        else:
            # Se o consentimento já foi dado, redireciona para o dashboard
            return jsonify({
                'status': 'success',
                'title': 'Login bem-sucedido',
                'message': 'Você será redirecionado...',
                'redirect': url_for('dashboard')
            })

    # Para requisições GET, renderiza o template de login. O JS no frontend cuidará do modal.
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

            # Verifica se o CNPJ já está sendo usado por *qualquer* outro usuário
            if cnpjs_collection.find_one({'cnpj': formatted_cnpj}):
                return jsonify({
                    'status': 'error',
                    'title': 'CNPJ em uso',
                    'message': 'Este CNPJ já está cadastrado.'
                }), 400
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
            'cnpj': formatted_cnpj, # Armazena o CNPJ no documento do usuário também
            'created_at': datetime.now(),
            'consent_given': False, # Novo usuário SEMPRE começa com consentimento NÃO dado
            'profile_pic': 'user-icon-pequeno.png' # Foto de perfil padrão
        }

        result = users_collection.insert_one(user_data)
        new_user_id = str(result.inserted_id)

        # Autentica o usuário recém-cadastrado na sessão
        session['username'] = username
        session['user_id'] = new_user_id
        session['consent_given'] = False # Garante que a sessão reflita o status de consentimento


        # Se um CNPJ foi fornecido, insere na coleção de CNPJs e cria uma entrada de empresa associada
        if formatted_cnpj:
            # Insere/Atualiza o CNPJ na coleção de controle de CNPJs com o user_id
            cnpjs_collection.update_one(
                {'cnpj': formatted_cnpj},
                {'$set': {'cnpj': formatted_cnpj, 'user_id': ObjectId(new_user_id)}}, # Use ObjectId para o user_id no DB
                upsert=True
            )

            # Cria ou atualiza a entrada da empresa na companies_collection
            company_data = {
                'name': username, # Nome inicial da empresa pode ser o nome de usuário
                'cnpj': formatted_cnpj,
                'description': f'Empresa de {username} no BusinessHub',
                'logo': 'company-default.png', # Logo padrão
                'owner_id': new_user_id, # Associa a empresa ao ID do usuário (como string)
                'created_at': datetime.now()
            }
            companies_collection.insert_one(company_data) # Insere uma nova empresa para o novo CNPJ/usuário

        # Redireciona para a página de login com o parâmetro para exibir o modal de consentimento
        return jsonify({
            'status': 'success',
            'title': 'Cadastro realizado!',
            'message': 'Seu cadastro foi concluído com sucesso. Por favor, aceite os termos para continuar.',
            'redirect': url_for('login', require_consent=True) # Redireciona para a página de login com o parâmetro
        })

    return render_template('login.html') # A página de registro geralmente é acessada a partir do login


@app.route('/api/initial_consent', methods=['POST'])
def initial_consent():
    """
    Endpoint dedicado para registrar o consentimento inicial do usuário.
    Este endpoint será chamado pelo modal de consentimento.
    """
    if 'username' not in session or 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Sessão expirada ou não autenticado.'}), 401

    user_id = session['user_id']
    data = request.get_json()

    # Definir a lista de IDs de termos obrigatórios que o backend espera.
    # Esta lista DEVE ser consistente com os IDs dos checkboxes no frontend.
    required_consent_ids = [
        'consentCadastro', 'consentPerfilVisualizacao', 'consentPerfilParcerias',
        'consentPostagens', 'consentParcerias', 'consentChat',
        'consentContratosArmazenamento', 'consentContratosConfirmacao',
        'consentFinal' # Certifique-se de que este último termo está aqui
    ]

    # Gerar os termos extras exatamente como no frontend para validação no backend
    base_terms_ids = [
        'consentCadastro', 'consentPerfilVisualizacao', 'consentPerfilParcerias',
        'consentPostagens', 'consentParcerias', 'consentChat',
        'consentContratosArmazenamento', 'consentContratosConfirmacao'
    ]
    for i in range(1, 16): # Range de 1 a 15, totalizando 15 extras
        for base_term_id in base_terms_ids:
            required_consent_ids.append(f"{base_term_id}_extra{i}")

    all_accepted = True
    for term_id in required_consent_ids:
        # Verifica se o checkbox com este ID foi enviado como 'true'.
        # data.get(term_id) retorna True/False ou None se a chave não existir.
        # 'not data.get(term_id)' será True se for False ou None.
        if not data.get(term_id):
            all_accepted = False
            print(f"DEBUG: Termo não aceito: {term_id}") # Adiciona um print para depuração
            break

    if not all_accepted:
        return jsonify({'success': False, 'error': 'Por favor, aceite todos os termos para continuar.'}), 400

    # Se todos os termos obrigatórios foram aceitos
    users_collection.update_one(
        {'_id': ObjectId(user_id)},
        {'$set': {'consent_given': True}}
    )

    # AQUI ESTÁ A MUDANÇA PRINCIPAL: LIMPAR A SESSÃO APÓS O CONSENTIMENTO
    # Isso garante que o usuário seja deslogado e precise fazer login novamente.
    session.clear()

    # Retorna uma resposta de sucesso e o redirecionamento para a página de login.
    return jsonify({
        'success': True,
        'message': 'Consentimento registrado com sucesso! Por favor, faça login novamente.',
        'redirect': url_for('login') # Redireciona para a página de login
    })


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
    Requer autenticação E consentimento.
    """
    if 'username' not in session or 'user_id' not in session:
        return redirect(url_for('login'))

    # Verifica o status do consentimento na sessão
    if not session.get('consent_given', False):
        return redirect(url_for('login', require_consent=True))

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
    Requer autenticação e consentimento.
    """
    if 'user_id' not in session:
        return jsonify({'status': 'error', 'message': 'Não autenticado'}), 401

    # Verifica o status do consentimento na sessão
    if not session.get('consent_given', False):
        return jsonify({'error': 'Consentimento necessário'}), 403

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
            # Verifica se o CNPJ já está sendo usado por outro usuário que NÃO SEJA O ATUAL
            if cnpjs_collection.find_one({'cnpj': processed_new_cnpj, 'user_id': {'$ne': ObjectId(user_id)}}):
                return jsonify({'status': 'error', 'message': 'Este CNPJ já está cadastrado para outro usuário.'}), 400

            update_data['cnpj'] = processed_new_cnpj
            # Atualiza ou insere o CNPJ na coleção de cnpjs_collection associado ao user_id
            cnpjs_collection.update_one(
                {'user_id': ObjectId(user_id)}, # Encontra pelo user_id
                {'$set': {'cnpj': processed_new_cnpj, 'user_id': ObjectId(user_id)}},
                upsert=True
            )
            # Atualiza ou cria a empresa na companies_collection
            companies_collection.update_one(
                {'owner_id': user_id}, # owner_id é uma string aqui (session['user_id'])
                {'$set': {
                    'cnpj': processed_new_cnpj,
                    'name': current_user_doc.get('username', 'Empresa'), # Mantém o nome atual ou padrão
                    'updated_at': datetime.now()
                }},
                upsert=True
            )
        else: # Se o CNPJ foi removido (campo vazio)
            update_data['cnpj'] = None
            cnpjs_collection.delete_one({'user_id': ObjectId(user_id)}) # Remove da coleção de CNPJs
            companies_collection.delete_one({'owner_id': user_id}) # Remove a empresa associada

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

# --- Nova Rota de API para Verificar Status de Autenticação e Consentimento ---
# Adicionado para resolver o erro 404 para /api/check-auth
@app.route('/api/check-auth')
@app.route('/api/check_consent_status') # Mantém a rota antiga para compatibilidade
def check_authentication_and_consent_status():
    """
    Endpoint para o frontend verificar rapidamente o status de autenticação e consentimento.
    Unifica a lógica para /api/check-auth e /api/check_consent_status.
    """
    authenticated = 'username' in session and 'user_id' in session
    consent_given = False
    if authenticated:
        user = users_collection.find_one({'_id': ObjectId(session['user_id'])}, {'consent_given': 1})
        if user:
            consent_given = user.get('consent_given', False)
            session['consent_given'] = consent_given # Garante que a sessão está atualizada

    return jsonify({
        'authenticated': authenticated,
        'consent_given': consent_given,
        'username': session.get('username') if authenticated else None,
        'user_id': session.get('user_id') if authenticated else None
    })


@app.route('/api/update_profile_pic', methods=['POST'])
def update_profile_pic():
    """
    Endpoint dedicado para a atualização da foto de perfil.
    É uma rota separada para maior granularidade e facilidade de uso do frontend.
    Requer autenticação e consentimento.
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Não autenticado'}), 401

    # Verifica o status do consentimento na sessão
    if not session.get('consent_given', False):
        return jsonify({'error': 'Consentimento necessário'}), 403

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
    Requer autenticação e consentimento.
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Não autenticado'}), 401

    # Verifica o status do consentimento na sessão
    if not session.get('consent_given', False):
        return jsonify({'error': 'Consentimento necessário'}), 403

    data = request.get_json()
    # Remove qualquer caractere que não seja dígito do CNPJ
    cnpj = re.sub(r'\D', '', data.get('cnpj', ''))

    if not cnpj: # Se o CNPJ for vazio, o usuário quer remover a empresa
        # Remove o CNPJ do usuário
        users_collection.update_one(
            {'_id': ObjectId(session['user_id'])},
            {'$set': {'cnpj': None}}
        )
        # Remove a entrada do CNPJ da cnpjs_collection
        cnpjs_collection.delete_one({'user_id': ObjectId(session['user_id'])})
        # Remove a empresa da companies_collection
        companies_collection.delete_one({'owner_id': session['user_id']})
        return jsonify({'success': 'Informações da empresa removidas com sucesso!'})

    if len(cnpj) != 14:
        return jsonify({'error': 'CNPJ inválido. Deve conter 14 dígitos.'}), 400

    # Verifica se o CNPJ já está em uso por outro usuário
    # Ao atualizar, precisamos garantir que o CNPJ não seja de outro usuário.
    # O user_id associado ao CNPJ na cnpjs_collection deve ser diferente do user_id atual.
    existing_cnpj_record = cnpjs_collection.find_one({'cnpj': cnpj})
    if existing_cnpj_record and str(existing_cnpj_record.get('user_id')) != session['user_id']:
            return jsonify({'error': 'Este CNPJ já está cadastrado para outro usuário.'}), 400


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

        # Atualiza ou insere o CNPJ na coleção de controle de CNPJs, associando-o ao user_id
        cnpjs_collection.update_one(
            {'user_id': ObjectId(session['user_id'])}, # Encontra pelo user_id
            {'$set': {'cnpj': cnpj, 'user_id': ObjectId(session['user_id'])}},
            upsert=True
        )

        # Atualiza ou cria a empresa na coleção `companies_collection`
        companies_collection.update_one(
            {'owner_id': session['user_id']}, # Associa ao user_id da sessão (string)
            {'$set': {
                'cnpj': cnpj,
                'name': company_data.get('fantasia', company_data.get('nome', 'Empresa')), # Prefere fantasia, senão nome, senão "Empresa"
                'data': company_data, # Armazena todos os dados da API
                'updated_at': datetime.now()
            }},
            upsert=True
        )

        return jsonify({
            'success': 'Dados da empresa atualizados com sucesso!',
            'company': company_data # Retorna os dados completos para o frontend atualizar
        })

    except requests.exceptions.RequestException as e:
        # Captura erros de requisição HTTP (conexão, timeout, etc.)
        return jsonify({'error': f'Erro de comunicação com a API da Receita WS: {str(e)}'}), 500
    except Exception as e:
        # Captura outros erros inesperados
        return jsonify({'error': f'Erro interno ao processar dados da empresa: {str(e)}'}), 500


@app.route('/termos_completos')
def termos_completos():
    """
    Renderiza a página com os termos de uso e política de privacidade completos.
    """
    return render_template('termos_completos.html')


# --- Execução da Aplicação ---
if __name__ == '__main__':
    # Cria as pastas de upload se elas não existirem
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['PROFILE_PICS_FOLDER'], exist_ok=True)
    os.makedirs(app.config['IMAGES_FOLDER'], exist_ok=True) # Criar pasta 'images'
    app.run(debug=False)
