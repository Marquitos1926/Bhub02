from flask import Flask, request, jsonify, redirect, url_for, render_template, session, send_from_directory
import re
import os
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta, datetime
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError # Import specific PyMongo errors
from bson.objectid import ObjectId
from bson import json_util
import json
import requests
import random
import logging # Import the logging module

# Configure logging
logging.basicConfig(level=logging.ERROR,
                    format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s')

app = Flask(__name__, template_folder='templates')

# --- Configurações da Aplicação ---
app.secret_key = os.environ.get('FLASK_SECRET_KEY', os.urandom(24))
if not app.secret_key:
    logging.warning("FLASK_SECRET_KEY environment variable not set. Using a random key for development. Set a strong key in production!")
    app.secret_key = os.urandom(24) # Fallback for local dev, but should be set in prod

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'static', 'uploads')
app.config['PROFILE_PICS_FOLDER'] = os.path.join(BASE_DIR, 'static', 'profile_pics')
app.config['IMAGES_FOLDER'] = os.path.join(BASE_DIR, 'static', 'images')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# --- Conexão com MongoDB ---
# IMPORTANT: Configure the MONGO_URI environment variable on Render!
mongo_uri = os.environ.get("MONGO_URI")
if not mongo_uri:
    logging.error("MONGO_URI environment variable is not set. Using fallback default URI.")
    # Fallback to a default or raise an error if not set (for local dev)
    # For production, it's critical that this is set.
    mongo_uri = "mongodb+srv://juliocardoso:1XIo2RrBrHSMZEIl@bd-bhub.pmuu5go.mongodb.net/?retryWrites=true&w=majority&appName=BD-BHUB" # Your default URI

# Global client and db, but connect within a try-except
client = None
db = None
try:
    # Increased serverSelectionTimeoutMS for more robust connection attempt
    client = MongoClient(mongo_uri, serverSelectionTimeoutMS=10000) # 10 second timeout
    # The ismaster command is cheap and does not require auth.
    client.admin.command('ismaster') 
    db = client.get_database("dbbhub")
    logging.info("Successfully connected to MongoDB.")
except ServerSelectionTimeoutError as err:
    logging.error(f"MongoDB Server Selection Timeout Error: {err}", exc_info=True)
    # db remains None, check_db_connection will handle
except ConnectionFailure as err:
    logging.error(f"MongoDB Connection Failure: {err}", exc_info=True)
except Exception as err:
    logging.error(f"An unexpected error occurred while connecting to MongoDB: {err}", exc_info=True)

# --- Coleções do Banco de Dados ---
# Initialize collections only if db connection was successful
if db:
    users_collection = db.users
    cnpjs_collection = db.cnpjs
    posts_collection = db.posts
    companies_collection = db.companies
    conversations_collection = db.conversations
    connection_requests_collection = db.connection_requests
else:
    # Fallback if DB connection failed (e.g., mock collections or exit)
    users_collection = None 
    cnpjs_collection = None
    posts_collection = None
    companies_collection = None
    conversations_collection = None
    connection_requests_collection = None

# Middleware to check DB connection status before each request
@app.before_request
def check_db_connection():
    if not db:
        logging.error("Database connection is not established. All DB operations will fail.")
        # For API routes, return JSON error
        if request.path.startswith('/api/'):
            return jsonify({'status': 'error', 'title': 'Erro de Serviço', 'message': 'O serviço está temporariamente indisponível. Por favor, tente novamente mais tarde.'}), 503
        # For non-API routes, redirect to a generic error/maintenance page
        # THIS IS WHERE THE TEMPLATE_NOT_FOUND ERROR WAS OCCURRING
        return render_template('maintenance.html', error_message="Nosso serviço está indisponível no momento. Por favor, tente novamente mais tarde.")


# --- Funções Auxiliares (Helpers) para Validação ---
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
    try:
        if users_collection is None: # Check if collection is initialized
            logging.error("users_collection not initialized. Database connection failed.")
            return None
        user = users_collection.find_one({'username': username})
        if user:
            user['_id'] = str(user['_id'])
            if 'profile_pic' not in user or not user['profile_pic']:
                user['profile_pic'] = 'user-icon-pequeno.png'
            user['consent_given'] = user.get('consent_given', False)
        return user
    except Exception as e:
        logging.error(f"Error fetching user data for {username}: {e}", exc_info=True)
        return None

# --- Rotas Principais da Aplicação ---
@app.route('/')
def home():
    if 'username' in session and 'user_id' in session and session.get('consent_given', False):
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/test-server')
def test_server():
    try:
        if users_collection is None:
            db_status = "Not connected to MongoDB (collection not initialized)."
        else:
            # Attempt a simple DB operation to test connectivity
            users_collection.find_one({})
            db_status = "Connected to MongoDB successfully."
    except Exception as e:
        db_status = f"Failed to connect to MongoDB: {e}"
    return f"Servidor Flask está funcionando! 🎉 DB Status: {db_status}"

@app.route('/dashboard')
def dashboard():
    if 'username' not in session or 'user_id' not in session:
        return redirect(url_for('login'))

    if not session.get('consent_given', False):
        return redirect(url_for('login', require_consent=True))

    user = get_user_data(session['username'])
    if not user:
        session.clear()
        return redirect(url_for('login'))

    try:
        if posts_collection is None or users_collection is None:
            raise Exception("Database collections not initialized.")

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

        return render_template('Dashboard.html',
                               username=session['username'],
                               user=user,
                               posts=posts)
    except Exception as e:
        logging.error(f"Error loading dashboard posts: {e}", exc_info=True)
        # Render with an error message or redirect
        return render_template('Dashboard.html', username=session['username'], user=user, posts=[], error_message="Não foi possível carregar as publicações no momento. Verifique a conexão com o banco de dados.")


@app.route('/explore')
def explore():
    if 'username' not in session or 'user_id' not in session:
        return redirect(url_for('login'))

    if not session.get('consent_given', False):
        return redirect(url_for('login', require_consent=True))

    user = get_user_data(session['username'])
    if not user:
        session.clear()
        return redirect(url_for('login'))

    try:
        if posts_collection is None or users_collection is None:
            raise Exception("Database collections not initialized.")

        companies_posts = list(posts_collection.find().sort('created_at', -1).limit(20))
        for post in companies_posts:
            post['_id'] = str(post['_id'])
            post['author_id'] = str(post['author_id'])

            author_user = users_collection.find_one({'_id': ObjectId(post['author_id'])})
            if author_user:
                post['author_name'] = author_user.get('username', 'Usuário Desconhecido')
                post['author_profile_pic'] = author_user.get('profile_pic', 'user-icon-pequeno.png')
            else:
                post['author_name'] = 'Usuário Desconhecido'
                post['author_profile_pic'] = 'user-icon-pequeno.png'

            post['likes_count'] = len(post.get('likes', []))
            post['comments_count'] = len(post.get('comments', []))

            if 'image' in post and post['image']:
                post['display_image'] = url_for('static_uploads', filename=post['image'])
            else:
                post['display_image'] = url_for('static', filename='company-default.png')

        all_users = list(users_collection.find({}, {'username': 1, 'profile_pic': 1}))
        for u in all_users:
            u['_id'] = str(u['_id'])
            if 'profile_pic' not in u or not u['profile_pic']:
                u['profile_pic'] = 'user-icon-pequeno.png'
            u['status'] = 'online' if random.random() > 0.5 else 'offline'

        return render_template('explore.html',
                               username=session['username'],
                               user=user,
                               companies=companies_posts,
                               all_users=all_users)
    except Exception as e:
        logging.error(f"Error loading explore data: {e}", exc_info=True)
        return render_template('explore.html', username=session['username'], user=user, companies=[], all_users=[], error_message="Não foi possível carregar o conteúdo de exploração no momento. Verifique a conexão com o banco de dados.")


@app.route('/messages')
def messages():
    if 'username' not in session or 'user_id' not in session:
        return redirect(url_for('login'))

    if not session.get('consent_given', False):
        return redirect(url_for('login', require_consent=True))

    user = get_user_data(session['username'])
    if not user:
        session.clear()
        return redirect(url_for('login'))

    current_user_id = user['_id']

    try:
        if conversations_collection is None or users_collection is None or connection_requests_collection is None:
            raise Exception("Database collections not initialized.")

        conversations = list(conversations_collection.find({
            'participants': current_user_id
        }).sort('last_message_at', -1))

        formatted_conversations = []
        for convo in conversations:
            convo['_id'] = str(convo['_id'])

            other_participant_id = None
            for p_id in convo['participants']:
                if p_id != current_user_id:
                    other_participant_id = p_id
                    break

            if not other_participant_id:
                continue

            other_user_info = users_collection.find_one({'_id': ObjectId(other_participant_id)}, {'username': 1, 'profile_pic': 1})
            if other_user_info:
                other_user_info['_id'] = str(other_user_info['_id'])
                if 'profile_pic' not in other_user_info or not other_user_info['profile_pic']:
                    other_user_info['profile_pic'] = 'user-icon-pequeno.png'

                convo['other_participant'] = other_user_info

                if convo.get('messages'):
                    convo['last_message_content'] = convo['messages'][-1]['content']
                    convo['last_message_time'] = convo['messages'][-1]['timestamp'].strftime('%H:%M')
                else:
                    convo['last_message_content'] = 'Nenhuma mensagem'
                    convo['last_message_time'] = ''

                formatted_conversations.append(convo)
            else:
                convo['other_participant'] = {'username': 'Usuário Desconhecido', 'profile_pic': 'user-icon-pequeno.png', '_id': None}
                if convo.get('messages'):
                    convo['last_message_content'] = convo['messages'][-1]['content']
                    convo['last_message_time'] = ''
                else:
                    convo['last_message_content'] = 'Nenhuma mensagem'
                    convo['last_message_time'] = ''
                formatted_conversations.append(convo)

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
    except Exception as e:
        logging.error(f"Error loading messages data: {e}", exc_info=True)
        return render_template('messages.html', user=user, conversations=[], pending_requests=[], error_message="Não foi possível carregar as mensagens no momento. Verifique a conexão com o banco de dados.")

@app.route('/static/uploads/<filename>')
def static_uploads(filename):
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except Exception as e:
        logging.error(f"Error serving static upload file {filename}: {e}", exc_info=True)
        return "", 404 # Not found

# --- Endpoints da API ---
@app.route('/api/companies')
def api_companies():
    if 'username' not in session or 'user_id' not in session:
        return jsonify({'error': 'Não autenticado'}), 401

    if not session.get('consent_given', False):
        return jsonify({'error': 'Consentimento necessário'}), 403

    try:
        if companies_collection is None:
            raise Exception("Database collection 'companies' not initialized.")
        companies = list(companies_collection.find({}, {'name': 1, 'description': 1, 'logo': 1}))
        for company in companies:
            company['_id'] = str(company['_id'])
        return json.loads(json_util.dumps(companies))
    except Exception as e:
        logging.error(f"Error in api_companies: {e}", exc_info=True)
        return jsonify({'error': 'Erro ao buscar dados de empresas.'}), 500

@app.route('/api/posts')
def api_posts():
    if 'username' not in session or 'user_id' not in session:
        return jsonify({'error': 'Não autenticado'}), 401

    if not session.get('consent_given', False):
        return jsonify({'error': 'Consentimento necessário'}), 403

    try:
        if posts_collection is None or users_collection is None:
            raise Exception("Database collections 'posts' or 'users' not initialized.")
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
    except Exception as e:
        logging.error(f"Error in api_posts: {e}", exc_info=True)
        return jsonify({'error': 'Erro ao buscar publicações.'}), 500

@app.route('/api/create_post', methods=['POST'])
def create_post():
    if 'username' not in session or 'user_id' not in session:
        return jsonify({'error': 'Não autenticado'}), 401

    if not session.get('consent_given', False):
        return jsonify({'error': 'Consentimento necessário'}), 403

    content = request.form.get('content')
    user_id = session.get('user_id')
    username = session.get('username')

    try:
        if users_collection is None or posts_collection is None:
            raise Exception("Database collections not initialized.")

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
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                post_data['image'] = filename

        posts_collection.insert_one(post_data)
        return jsonify({'success': 'Post criado com sucesso!'})
    except Exception as e:
        logging.error(f"Error creating post: {e}", exc_info=True)
        return jsonify({'error': f'Erro interno ao criar post: {str(e)}'}), 500

@app.route('/api/like_post/<post_id>', methods=['POST'])
def like_post(post_id):
    if 'username' not in session or 'user_id' not in session:
        return jsonify({'error': 'Não autenticado'}), 401

    if not session.get('consent_given', False):
        return jsonify({'error': 'Consentimento necessário'}), 403

    user_id = session['user_id']

    try:
        if posts_collection is None:
            raise Exception("Database collection 'posts' not initialized.")
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
        logging.error(f"Error processing like for post {post_id}: {e}", exc_info=True)
        return jsonify({'error': f'Erro interno ao processar like: {str(e)}'}), 500

@app.route('/api/conversations/<conversation_id>')
def get_conversation_messages(conversation_id):
    if 'username' not in session or 'user_id' not in session:
        return jsonify({'error': 'Não autenticado'}), 401

    if not session.get('consent_given', False):
        return jsonify({'error': 'Consentimento necessário'}), 403

    current_user_id = session['user_id']

    try:
        if conversations_collection is None:
            raise Exception("Database collection 'conversations' not initialized.")
        conversation = conversations_collection.find_one({'_id': ObjectId(conversation_id)})
        if not conversation:
            return jsonify({'error': 'Conversa não encontrada.'}), 404

        if current_user_id not in conversation['participants']:
            return jsonify({'error': 'Você não tem permissão para acessar esta conversa.'}), 403

        messages = conversation.get('messages', [])
        for msg in messages:
            msg['_id'] = str(msg['_id'])
            msg['timestamp_formatted'] = msg['timestamp'].strftime('%d/%m/%Y %H:%M')

        return json.loads(json_util.dumps(messages))
    except Exception as e:
        logging.error(f"Error getting conversation messages {conversation_id}: {e}", exc_info=True)
        return jsonify({'error': f'Erro interno ao buscar mensagens da conversa: {str(e)}'}), 500


@app.route('/api/send_message', methods=['POST'])
def send_message():
    if 'username' not in session or 'user_id' not in session:
        return jsonify({'error': 'Não autenticado'}), 401

    if not session.get('consent_given', False):
        return jsonify({'error': 'Consentimento necessário'}), 403

    data = request.get_json()
    receiver_id = data.get('receiver_id')
    message_content = data.get('message_content')

    if not receiver_id or not message_content:
        return jsonify({'error': 'Destinatário e conteúdo da mensagem são necessários.'}), 400

    sender_id = session['user_id']

    try:
        if users_collection is None or conversations_collection is None:
            raise Exception("Database collections not initialized.")

        receiver_obj_id = ObjectId(receiver_id)
        receiver_user = users_collection.find_one({'_id': receiver_obj_id})
        if not receiver_user:
            return jsonify({'error': 'Destinatário não encontrado.'}), 404
    except Exception as e: # Catch error for ObjectId conversion or DB lookup
        logging.error(f"Error validating receiver ID for message: {e}", exc_info=True)
        return jsonify({'error': 'ID de destinatário inválido ou erro de DB.'}), 400 # Changed error message for clarity

    try:
        conversation = conversations_collection.find_one({
            'participants': { '$all': [sender_id, receiver_id] },
            'is_group': False
        })

        new_message = {
            '_id': ObjectId(),
            'sender_id': sender_id,
            'content': message_content,
            'timestamp': datetime.now()
        }

        if conversation:
            conversations_collection.update_one(
                {'_id': conversation['_id']},
                {
                    '$push': {'messages': new_message},
                    '$set': {'last_message_at': datetime.now()}
                }
            )
            conversation_id = str(conversation['_id'])
        else:
            new_conversation = {
                'participants': [sender_id, receiver_id],
                'messages': [new_message],
                'created_at': datetime.now(),
                'last_message_at': datetime.now(),
                'is_group': False
            }
            result = conversations_collection.insert_one(new_conversation)
            conversation_id = str(result.inserted_id)

        return jsonify({
            'success': 'Mensagem enviada com sucesso!',
            'conversation_id': conversation_id,
            'message_id': str(new_message['_id']),
            'timestamp': new_message['timestamp'].isoformat()
        })
    except Exception as e:
        logging.error(f"Error sending message: {e}", exc_info=True)
        return jsonify({'error': f'Erro interno ao enviar mensagem: {str(e)}'}), 500


@app.route('/api/send_connection_request', methods=['POST'])
def send_connection_request():
    if 'username' not in session or 'user_id' not in session:
        return jsonify({'error': 'Não autenticado'}), 401

    if not session.get('consent_given', False):
        return jsonify({'error': 'Consentimento necessário'}), 403

    data = request.get_json()
    receiver_id = data.get('receiver_id')

    if not receiver_id:
        return jsonify({'error': 'ID do destinatário é necessário.'}), 400

    sender_id = session['user_id']

    if sender_id == receiver_id:
        return jsonify({'error': 'Você não pode enviar uma solicitação de conexão para si mesmo.'}), 400

    try:
        if connection_requests_collection is None or users_collection is None:
            raise Exception("Database collections not initialized.")

        existing_request = connection_requests_collection.find_one({
            '$or': [
                {'sender_id': sender_id, 'receiver_id': receiver_id},
                {'sender_id': receiver_id, 'receiver_id': sender_id}
            ]
        })

        if existing_request:
            if existing_request['status'] == 'pending':
                if existing_request['sender_id'] == sender_id:
                    return jsonify({'error': 'Você já enviou uma solicitação para este usuário.'}), 400
                else:
                    return jsonify({'error': 'Este usuário já enviou uma solicitação para você. Por favor, aceite-a na área de solicitações.'}), 400
            elif existing_request['status'] == 'accepted':
                return jsonify({'error': 'Vocês já estão conectados.'}), 400

        receiver_user = users_collection.find_one({'_id': ObjectId(receiver_id)})
        if not receiver_user:
            return jsonify({'error': 'Usuário destinatário não encontrado.'}), 404

        request_data = {
            'sender_id': sender_id,
            'receiver_id': receiver_id,
            'status': 'pending',
            'sent_at': datetime.now()
        }
        connection_requests_collection.insert_one(request_data)

        return jsonify({'success': 'Solicitação de conexão enviada com sucesso!'})
    except Exception as e:
        logging.error(f"Error sending connection request: {e}", exc_info=True)
        return jsonify({'error': f'Erro interno ao enviar solicitação de conexão: {str(e)}'}), 500


@app.route('/api/respond_connection_request', methods=['POST'])
def respond_connection_request():
    if 'username' not in session or 'user_id' not in session:
        return jsonify({'error': 'Não autenticado'}), 401

    if not session.get('consent_given', False):
        return jsonify({'error': 'Consentimento necessário'}), 403

    data = request.get_json()
    request_id = data.get('request_id')
    action = data.get('action')

    if not request_id or action not in ['accept', 'reject']:
        return jsonify({'error': 'ID da solicitação e ação (accept/reject) são necessários.'}), 400

    current_user_id = session['user_id']

    try:
        if connection_requests_collection is None or conversations_collection is None:
            raise Exception("Database collections not initialized.")

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
            conversations_collection.update_one(
                {
                    'participants': { '$all': [connection_request['sender_id'], connection_request['receiver_id']] },
                    'is_group': False
                },
                {'$set': {
                    'participants': [connection_request['sender_id'], connection_request['receiver_id']],
                    'created_at': datetime.now(),
                    'messages': [],
                    'last_message_at': datetime.now()
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
    except Exception as e:
        logging.error(f"Error responding to connection request: {e}", exc_info=True)
        return jsonify({'error': f'Erro interno ao responder solicitação de conexão: {str(e)}'}), 500


@app.route('/api/search_users', methods=['GET'])
def search_users():
    if 'username' not in session or 'user_id' not in session:
        return jsonify({'error': 'Não autenticado'}), 401

    if not session.get('consent_given', False):
        return jsonify({'error': 'Consentimento necessário'}), 403

    query = request.args.get('q', '').strip()
    if not query:
        return jsonify([])

    current_user_id = session['user_id']
    try:
        if users_collection is None or connection_requests_collection is None:
            raise Exception("Database collections not initialized.")

        users = list(users_collection.find(
            {
                'username': {'$regex': query, '$options': 'i'},
                '_id': {'$ne': ObjectId(current_user_id)}
            },
            {'username': 1, 'profile_pic': 1}
        ).limit(10))

        for u in users:
            u['_id'] = str(u['_id'])
            if 'profile_pic' not in u or not u['profile_pic']:
                u['profile_pic'] = 'user-icon-pequeno.png'

            existing_connection = connection_requests_collection.find_one({
                '$or': [
                    {'sender_id': current_user_id, 'receiver_id': u['_id']},
                    {'sender_id': u['_id'], 'receiver_id': current_user_id}
                ]
            })

            if existing_connection:
                u['connection_status'] = existing_connection['status']
                if existing_connection['sender_id'] == current_user_id and existing_connection['status'] == 'pending':
                    u['pending_sent_by_me'] = True
                u['request_id'] = str(existing_connection['_id'])
            else:
                u['connection_status'] = 'none'

        return json.loads(json_util.dumps(users))
    except Exception as e:
        logging.error(f"Error searching users: {e}", exc_info=True)
        return jsonify({'error': f'Erro interno ao buscar usuários: {str(e)}'}), 500

# --- Rotas de Autenticação ---
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

        try:
            if users_collection is None:
                raise Exception("Database collection 'users' not initialized.")
            user = users_collection.find_one({'username': username})

            if not user or not check_password_hash(user['password'], password):
                return jsonify({
                    'status': 'error',
                    'title': 'Falha no login',
                    'message': 'Credenciais inválidas.'
                }), 401

            session['username'] = username
            session['user_id'] = str(user['_id'])
            session['consent_given'] = user.get('consent_given', False)

            if remember:
                session.permanent = True
                app.permanent_session_lifetime = timedelta(days=30)

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
                    'title': 'Login bem-sucedido',
                    'message': 'Você será redirecionado...',
                    'redirect': url_for('dashboard')
                })

        except Exception as e:
            logging.error(f"Unhandled exception during login POST: {e}", exc_info=True)
            return jsonify({
                'status': 'error',
                'title': 'Erro Interno do Servidor',
                'message': 'Não foi possível completar o login devido a um problema no servidor. Por favor, tente novamente.'
            }), 500

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

        try:
            if users_collection is None or cnpjs_collection is None or companies_collection is None:
                raise Exception("Database collections not initialized.")

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
            new_user_id = str(result.inserted_id)

            session['username'] = username
            session['user_id'] = new_user_id
            session['consent_given'] = False

            if formatted_cnpj:
                cnpjs_collection.update_one(
                    {'cnpj': formatted_cnpj},
                    {'$set': {'cnpj': formatted_cnpj, 'user_id': ObjectId(new_user_id)}},
                    upsert=True
                )

                company_data = {
                    'name': username,
                    'cnpj': formatted_cnpj,
                    'description': f'Empresa de {username} no BusinessHub',
                    'logo': 'company-default.png',
                    'owner_id': new_user_id,
                    'created_at': datetime.now()
                }
                companies_collection.insert_one(company_data)

            return jsonify({
                'status': 'success',
                'title': 'Cadastro realizado!',
                'message': 'Seu cadastro foi concluído com sucesso. Por favor, aceite os termos para continuar.',
                'redirect': url_for('login', require_consent=True)
            })

        except Exception as e:
            logging.error(f"Unhandled exception during register POST: {e}", exc_info=True)
            return jsonify({
                'status': 'error',
                'title': 'Erro Interno do Servidor',
                'message': 'Não foi possível completar o registro devido a um problema no servidor. Por favor, tente novamente.'
            }), 500

    return render_template('login.html')


@app.route('/api/initial_consent', methods=['POST'])
def initial_consent():
    if 'username' not in session or 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Sessão expirada ou não autenticado.'}), 401

    user_id = session['user_id']
    data = request.get_json()

    required_consent_ids = [
        'consentCadastro', 'consentPerfilVisualizacao', 'consentPerfilParcerias',
        'consentPostagens', 'consentParcerias', 'consentChat',
        'consentContratosArmazenamento', 'consentContratosConfirmacao',
        'consentFinal'
    ]

    base_terms_ids = [
        'consentCadastro', 'consentPerfilVisualizacao', 'consentPerfilParcerias',
        'consentPostagens', 'consentParcerias', 'consentChat',
        'consentContratosArmazenamento', 'consentContratosConfirmacao'
    ]
    for i in range(1, 16):
        for base_term_id in base_terms_ids:
            required_consent_ids.append(f"{base_term_id}_extra{i}")

    all_accepted = True
    for term_id in required_consent_ids:
        if not data.get(term_id):
            all_accepted = False
            logging.debug(f"DEBUG: Termo não aceito: {term_id}")
            break

    if not all_accepted:
        return jsonify({'success': False, 'error': 'Por favor, aceite todos os termos para continuar.'}), 400

    try:
        if users_collection is None:
            raise Exception("Database collection 'users' not initialized.")
        users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'consent_given': True}}
        )
        session.clear()
        return jsonify({
            'success': True,
            'message': 'Consentimento registrado com sucesso! Por favor, faça login novamente.',
            'redirect': url_for('login')
        })
    except Exception as e:
        logging.error(f"Error registering consent: {e}", exc_info=True)
        return jsonify({'success': False, 'error': f'Erro interno ao registrar consentimento: {str(e)}'}), 500


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# --- Rotas de Perfil ---
@app.route('/perfil')
def show_profile():
    if 'username' not in session or 'user_id' not in session:
        return redirect(url_for('login'))

    if not session.get('consent_given', False):
        return redirect(url_for('login', require_consent=True))

    user = get_user_data(session['username'])
    if not user:
        session.clear()
        return redirect(url_for('login'))

    company = None
    try:
        if companies_collection is None: # Added check
            raise Exception("Database collection 'companies' not initialized.")
        if 'cnpj' in user and user['cnpj']:
            company = companies_collection.find_one({'owner_id': user['_id']})
            if company:
                company['_id'] = str(company['_id'])
    except Exception as e:
        logging.error(f"Error fetching company data for profile: {e}", exc_info=True)
        # Continue rendering, but company will be None or partially loaded
    
    return render_template('perfil.html', user=user, company=company)

@app.route('/api/update_profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return jsonify({'status': 'error', 'message': 'Não autenticado'}), 401

    if not session.get('consent_given', False):
        return jsonify({'error': 'Consentimento necessário'}), 403

    user_id = session['user_id']
    
    try:
        if users_collection is None or cnpjs_collection is None or companies_collection is None:
            raise Exception("Database collections not initialized.")

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
                if cnpjs_collection.find_one({'cnpj': processed_new_cnpj, 'user_id': {'$ne': ObjectId(user_id)}}):
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

        if update_data:
            users_collection.update_one(
                {'_id': ObjectId(user_id)},
                {'$set': update_data}
            )
            return jsonify({'status': 'success', 'message': 'Perfil atualizado com sucesso!'})
        else:
            return jsonify({'status': 'info', 'message': 'Nenhuma alteração a ser salva.'})
    except Exception as e:
        logging.error(f"Unhandled exception during update_profile POST: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'title': 'Erro Interno do Servidor',
            'message': 'Não foi possível atualizar o perfil devido a um problema no servidor. Por favor, tente novamente.'
        }), 500


# --- Rotas de Recuperação de Senha ---
@app.route('/recuperar_senha')
def show_recover_password():
    return render_template('recuperar_senha.html')

@app.route('/recover_password', methods=['POST'])
def recover_password():
    identifier = request.form.get('recoveryIdentifier')
    
    try:
        if users_collection is None:
            raise Exception("Database collection 'users' not initialized.")

        user = users_collection.find_one({'$or': [{'email': identifier}, {'username': identifier}]})

        if user:
            logging.info(f"Recovery request for: {identifier}. Simulated recovery email sent to {user['email']}")
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
    except Exception as e:
        logging.error(f"Unhandled exception during recover_password POST: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'title': 'Erro Interno do Servidor',
            'message': 'Não foi possível processar a recuperação de senha devido a um problema no servidor. Por favor, tente novamente.'
        }), 500


# --- Rotas para Arquivos Estáticos ---
@app.route('/static/<path:filename>')
def static_files(filename):
    try:
        return send_from_directory('static', filename)
    except Exception as e:
        logging.error(f"Error serving static file {filename}: {e}", exc_info=True)
        return "", 404 # Not found


# --- Nova Rota de API para Verificar Status de Autenticação e Consentimento ---
@app.route('/api/check-auth')
@app.route('/api/check_consent_status')
def check_authentication_and_consent_status():
    authenticated = 'username' in session and 'user_id' in session
    consent_given = False
    if authenticated:
        try:
            if users_collection is None:
                raise Exception("Database collection 'users' not initialized.")
            user = users_collection.find_one({'_id': ObjectId(session['user_id'])}, {'consent_given': 1})
            if user:
                consent_given = user.get('consent_given', False)
                session['consent_given'] = consent_given
        except Exception as e:
            logging.error(f"Error verifying consent status from DB: {e}", exc_info=True)
            authenticated = False # Treat as unauthenticated if DB check fails
            consent_given = False

    return jsonify({
        'authenticated': authenticated,
        'consent_given': consent_given,
        'username': session.get('username') if authenticated else None,
        'user_id': session.get('user_id') if authenticated else None
    })


@app.route('/api/update_profile_pic', methods=['POST'])
def update_profile_pic():
    if 'user_id' not in session:
        return jsonify({'error': 'Não autenticado'}), 401

    if not session.get('consent_given', False):
        return jsonify({'error': 'Consentimento necessário'}), 403

    if 'profile_pic' not in request.files:
        return jsonify({'error': 'Nenhum arquivo fornecido'}), 400

    file = request.files['profile_pic']
    if file.filename == '':
        return jsonify({'error': 'Nenhum arquivo selecionado'}), 400

    if file and allowed_file(file.filename):
        try:
            if users_collection is None:
                raise Exception("Database collection 'users' not initialized.")

            filename = f"{session['user_id']}_{int(datetime.now().timestamp())}.{file.filename.rsplit('.', 1)[1].lower()}"
            filepath = os.path.join(app.config['PROFILE_PICS_FOLDER'], filename)
            file.save(filepath)

            user = users_collection.find_one({'_id': ObjectId(session['user_id'])})
            if user and 'profile_pic' in user and user['profile_pic'] != 'user-icon-pequeno.png':
                old_pic_path = os.path.join(app.config['PROFILE_PICS_FOLDER'], user['profile_pic'])
                if os.path.exists(old_pic_path):
                    try:
                        os.remove(old_pic_path)
                    except OSError as e:
                        logging.warning(f"Could not remove old profile picture {old_pic_path}: {e}")

            users_collection.update_one(
                {'_id': ObjectId(session['user_id'])},
                {'$set': {'profile_pic': filename}}
            )

            return jsonify({'success': 'Foto de perfil atualizada!', 'filename': filename})
        except Exception as e:
            logging.error(f"Unhandled exception during update_profile_pic POST: {e}", exc_info=True)
            return jsonify({
                'error': 'Ocorreu um erro ao atualizar a foto de perfil. Por favor, tente novamente.'
            }), 500

    return jsonify({'error': 'Tipo de arquivo não permitido'}), 400

@app.route('/api/update_company', methods=['POST'])
def update_company():
    if 'user_id' not in session:
        return jsonify({'error': 'Não autenticado'}), 401

    if not session.get('consent_given', False):
        return jsonify({'error': 'Consentimento necessário'}), 403

    data = request.get_json()
    cnpj = re.sub(r'\D', '', data.get('cnpj', ''))

    try:
        if users_collection is None or cnpjs_collection is None or companies_collection is None:
            raise Exception("Database collections not initialized.")

        if not cnpj:
            users_collection.update_one(
                {'_id': ObjectId(session['user_id'])},
                {'$set': {'cnpj': None}}
            )
            cnpjs_collection.delete_one({'user_id': ObjectId(session['user_id'])})
            companies_collection.delete_one({'owner_id': session['user_id']})
            return jsonify({'success': 'Informações da empresa removidas com sucesso!'})

        if len(cnpj) != 14:
            return jsonify({'error': 'CNPJ inválido. Deve conter 14 dígitos.'}), 400

        existing_cnpj_record = cnpjs_collection.find_one({'cnpj': cnpj})
        if existing_cnpj_record and str(existing_cnpj_record.get('user_id')) != session['user_id']:
            return jsonify({'error': 'Este CNPJ já está cadastrado para outro usuário.'}), 400

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

        cnpjs_collection.update_one(
            {'user_id': ObjectId(session['user_id'])},
            {'$set': {'cnpj': cnpj, 'user_id': ObjectId(session['user_id'])}},
            upsert=True
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
        logging.error(f"API de Receita WS Request Error: {e}", exc_info=True)
        return jsonify({'error': f'Erro de comunicação com a API da Receita WS: {str(e)}'}), 500
    except Exception as e:
        logging.error(f"Unhandled exception during update_company POST: {e}", exc_info=True)
        return jsonify({'error': f'Erro interno ao processar dados da empresa: {str(e)}'}), 500

@app.route('/termos_completos')
def termos_completos():
    return render_template('termos_completos.html')

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['PROFILE_PICS_FOLDER'], exist_ok=True)
    os.makedirs(app.config['IMAGES_FOLDER'], exist_ok=True)
    app.run(debug=False)
