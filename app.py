import os
from datetime import datetime, timedelta
import re
from flask import Flask, redirect, request, jsonify
from flask_mail import Mail, Message
import random
import jwt
from supabase import create_client, Client
import firebase_admin
from firebase_admin import credentials, messaging
from flask_talisman import Talisman
import bcrypt
from dotenv import load_dotenv
import secrets
import string
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import json
from werkzeug.middleware.proxy_fix import ProxyFix

# Load environment variables
load_dotenv()

cred = credentials.Certificate(os.getenv('FIREBASE_ADMIN_SDK_PATH', 'telecrypt-8ffd5-firebase-adminsdk-fbsvc-80b35fc77b.json'))
firebase_admin.initialize_app(cred)

def send_fcm_notification(fcm_token, message):
    message = messaging.Message(
        notification=messaging.Notification(
            title='New Message',
            body=message,
        ),
        token=fcm_token,
    )

    response = messaging.send(message)
    print('Successfully sent message:', response)

app = Flask(__name__)

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

talisman = Talisman(
    app,
    force_https=True,
    strict_transport_security=True,
    session_cookie_secure=True,
    content_security_policy={
        'default-src': "'self'",
        'img-src': ['*', 'data:'],
        'script-src': "'self'"
    }
)

app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() in ('true', '1', 't')
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

mail = Mail(app)

SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

try:
    with open(os.getenv('SERVER_PRIVATE_KEY_PATH', "server_private.pem"), "rb") as f:
        PRIVATE_KEY = f.read()

    with open(os.getenv('SERVER_PUBLIC_KEY_PATH', "server_public.pem"), "rb") as f:
        PUBLIC_KEY = f.read()
except Exception as e:
    print(f"Error loading keys: {e}")
    raise


JWT_EXPIRATION = int(os.getenv('JWT_EXPIRATION_SECONDS', 3600))  

def generate_secure_token(length=32):
    """Generate a cryptographically secure random token"""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def hash_password(password):
    """Hash a password using bcrypt with proper salting"""
   
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8') 

def verify_password(stored_hash, provided_password):
    """Verify a password against its stored hash"""
    stored_bytes = stored_hash.encode('utf-8')
    provided_bytes = provided_password.encode('utf-8')
    return bcrypt.checkpw(provided_bytes, stored_bytes)

def sign_dh_params(payload, expiration=JWT_EXPIRATION):
    """Sign DH parameters with added expiration"""
   
    expiry = datetime.utcnow() + timedelta(seconds=expiration)
    payload['exp'] = expiry.timestamp()
    
    signature = jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")
    return signature

def verify_dh_params(request_data, signature):
    """Verify DH parameters signature with expiration checking"""
    try:
        payload = jwt.decode(signature, PUBLIC_KEY, algorithms=["RS256"])
        
       
        required_fields = ["g", "m", "g^a", "sender_uuid", "sender_public_key", "reciever_uuid"]
        if not all(field in payload for field in required_fields):
            return False
        
        # Verify fields match
        for field in required_fields:
            if field in request_data and payload.get(field) != request_data.get(field):
                return False
                
        return True
    except jwt.ExpiredSignatureError:
        print("Signature has expired")
        return False
    except jwt.InvalidTokenError as e:
        print(f"Invalid token: {e}")
        return False

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def sanitize_input(input_str):
    """Basic input sanitization"""
    if not isinstance(input_str, str):
        return input_str
    
    # Remove potential XSS and SQL injection patterns
    dangerous_patterns = [
        r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>',  # script tags
        r'javascript:',  # javascript protocol
        r'--',  # SQL comment
        r';\s*DROP',  # SQL DROP statement
        r';\s*DELETE',  # SQL DELETE statement
        r'UNION\s+SELECT',  # SQL UNION
    ]
    
    result = input_str
    for pattern in dangerous_patterns:
        result = re.sub(pattern, '', result, flags=re.IGNORECASE)
    
    return result

def validate_request_json(*required_fields):
    """Decorator to validate request JSON data"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            data = request.get_json()
            
           
            if data is None:
                return jsonify({"error": "Missing JSON body"}), 400
            
            
            missing_fields = [field for field in required_fields if field not in data or data[field] is None]
            if missing_fields:
                return jsonify({"error": f"Missing required fields: {', '.join(missing_fields)}"}), 400
            
            
            for key in data:
                if isinstance(data[key], str):
                    data[key] = sanitize_input(data[key])
            
            return func(*args, **kwargs)
        
        wrapper.__name__ = func.__name__
        return wrapper
    
    return decorator


@app.before_request
def enforce_https():
    if not request.is_secure:
        return redirect(request.url.replace("http://", "https://"), code=301)

@app.before_request
def log_request():
    app.logger.info(f"Request: {request.method} {request.path} from {request.remote_addr}")

@app.after_request
def log_response(response):
    app.logger.info(f"Response: {response.status_code}")
    return response

@app.route('/send_otp', methods=['POST'])
@validate_request_json('email')
def send_otp():
    data = request.json
    email = data.get('email')

   
    if not validate_email(email):
        return jsonify({'error': 'Invalid email format'}), 400

    # Generate a secure OTP
    otp = ''.join(secrets.choice(string.digits) for _ in range(6))
    
    try:
        # Insert OTP with expiration time (30 minutes)
        expiry = datetime.utcnow() + timedelta(minutes=30)
        response = supabase.table("otp").insert({
            "email": email, 
            "otp": otp,
            "expires_at": expiry.isoformat()
        }).execute()

        # Send OTP Email
        msg = Message('Your OTP Code', recipients=[email])
        msg.body = f'Your OTP code is: {otp}\nThis code will expire in 30 minutes.'
        mail.send(msg)

        return jsonify({'message': 'OTP sent successfully'}), 200
    except Exception as e:
        app.logger.error(f"Error sending OTP: {str(e)}")
        return jsonify({'error': 'Failed to send OTP'}), 500

@app.route('/verify_otp', methods=['POST'])
@validate_request_json('email', 'otp')
def verify_otp():
    data = request.json
    email = data['email']
    otp = data['otp']

    try:
        # Check OTP from Supabase with expiration
        now = datetime.utcnow().isoformat()
        response = supabase.table("otp").select("otp").eq("email", email).gt("expires_at", now).execute()
        
        if not response.data:
            return jsonify({'error': 'OTP expired or not found'}), 400

        stored_otp = response.data[0]["otp"]

        if stored_otp == otp:
            # Delete OTP after successful verification
            supabase.table("otp").delete().eq("email", email).execute()
            return jsonify({'message': 'OTP verified successfully'})

        return jsonify({'error': 'Invalid OTP'}), 400
    except Exception as e:
        app.logger.error(f"Error verifying OTP: {str(e)}")
        return jsonify({'error': 'Failed to verify OTP'}), 500

@app.route('/insert_user', methods=['POST'])
@validate_request_json('name', 'email', 'password')
def insert_user():
    try:
        data = request.json

        username = data.get('name')
        email = data.get('email')
        password = data.get('password')
        bio = data.get('bio', "")
        dob = data.get('dob', "")
        profile_pic_url = data.get('profile_pic', "")

        # Validate email format
        if not validate_email(email):
            return jsonify({"error": "Invalid email format"}), 400

        # Hash the password using bcrypt
        hashed_password = hash_password(password)

        # Insert User Data into Supabase
        response = supabase.table('User').insert({
            "name": username,
            "email": email,
            "password": hashed_password,  # Store the bcrypt hashed password
            "bio": bio,
            "birth_date": dob,
            "profile_pic": profile_pic_url
        }).execute()

        # Extract inserted user data
        inserted_user = response.data if response.data else []
        if not inserted_user:
            return jsonify({"error": "Failed to retrieve user data"}), 500

        # Get the UUID of the newly inserted user
        user_uuid = inserted_user[0].get("id")  # Assuming 'id' is the UUID column

        return jsonify({
            "message": "User registered successfully",
            "uuid": user_uuid,
            "profile_pic_url": profile_pic_url
        }), 200

    except Exception as e:
        app.logger.error(f"Error inserting user: {str(e)}")
        return jsonify({"error": "Failed to register user"}), 500

@app.route('/verify_email', methods=['POST'])
@validate_request_json('email')
def verify_email():
    try:
        data = request.json
        email = data.get('email')
        
        # Validate email format
        if not validate_email(email):
            return jsonify({"error": "Invalid email format"}), 400

        response = supabase.table('User').select('email').eq('email', email).execute()
        if response.data and len(response.data) > 0:
            return jsonify({"exists": True}), 200
        else:
            return jsonify({"exists": False}), 200        

    except Exception as e:
        app.logger.error(f"Error verifying email: {str(e)}")
        return jsonify({"error": "Failed to verify email"}), 500

@app.route('/login', methods=['POST'])
@validate_request_json('email', 'password')
def login():
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')

        # Find user by email
        response = supabase.table('User').select('*').eq('email', email).execute()
        
        if not response.data or len(response.data) == 0:
            # Use constant-time comparison to prevent timing attacks
            # Just hash some dummy password to spend similar time
            hash_password("dummy_password")
            return jsonify({"error": "Invalid email or password"}), 401
            
        user = response.data[0]
        stored_password = user['password']
        
        # Verify password with bcrypt
        if verify_password(stored_password, password):
            # Generate session token if needed
            session_token = generate_secure_token()
            
            # Optional: Store session with expiry in your database
            
            return jsonify({
                "message": "Login successful", 
                "user": user,
                "session_token": session_token
            }), 200
        else:
            return jsonify({"error": "Invalid email or password"}), 401

    except Exception as e:
        app.logger.error(f"Error during login: {str(e)}")
        return jsonify({"error": "Login failed"}), 500

@app.route('/create_chat', methods=['POST'])
@validate_request_json('uuid', 'g', 'p', 'ga', 'public_key', 'reciever_uuid', 'password')
def create_chat():
    try:
        data = request.json
        
        sender_uuid = data.get('uuid')
        g = data.get('g')
        p = data.get('p')
        ga = data.get('ga')
        public_key = data.get('public_key')
        reciever_uuid = data.get('reciever_uuid')
        password = data.get('password')
        
        # Verify sender exists and password is correct
        response = supabase.table('User').select('password,id').eq('id', sender_uuid).execute()
        if len(response.data) == 0:
            return jsonify({"error": "User not found"}), 404
            
        user_stored_password = response.data[0]['password']
        
        # Verify password using bcrypt
        if not verify_password(user_stored_password, password):
            return jsonify({"error": "Authentication failed"}), 401
            
        # Sign the parameters with expiration
        signature = sign_dh_params({
            "sender_uuid": sender_uuid,
            "g": g,
            "m": p,
            "g^a": ga,
            "sender_public_key": public_key,
            "reciever_uuid": reciever_uuid,
            "created_at": datetime.utcnow().isoformat()
        })
        
        # Store the chat request
        response = supabase.table('chat_request').insert({
            "sender_uuid": sender_uuid,
            "g": g,
            "m": p,
            "g^a": ga,
            "sender_public_key": public_key,
            "reciever_uuid": reciever_uuid,
            'signature': signature
        }).execute()
        
        if response.data:
            return jsonify({"uuid": response.data[0]['id']}), 200
        else:
            return jsonify({"error": "Failed to create chat request"}), 500
            
    except Exception as e:
        app.logger.error(f"Error creating chat: {str(e)}")
        return jsonify({"error": "Failed to create chat"}), 500

@app.route('/get_users', methods=['GET'])
def get_users():
    try:
        word = str(request.args.get('word', ''))
        if not word:
            return jsonify({"error": "Missing required fields"}), 400
            
        # Sanitize input
        word = sanitize_input(word)
        safe_word = re.escape(word)
        
        response = supabase.rpc("search_users_by_name_or_email", {"prefix": safe_word}).execute()
        Users = []
        if response.data and len(response.data) > 0:
            for user in response.data:
                Users.append(user)
        return jsonify({"users": Users}), 200
    except Exception as e:
        app.logger.error(f"Error getting users: {str(e)}")
        return jsonify({"error": "Failed to search users"}), 500

@app.route('/get_request', methods=['GET'])
def get_request():
    try:
        request_id = str(request.args.get('uuid', ''))
        if not request_id:
            return jsonify({"error": "Missing required fields"}), 400
            
        # Sanitize input
        request_id = sanitize_input(request_id)
        
        response = supabase.from_("chat_request").select("*").eq("id", request_id).execute()
        if response.data and len(response.data) > 0:
            return jsonify({"request": response.data[0]}), 200
        else:
            return jsonify({"error": "Request not found"}), 404
    except Exception as e:
        app.logger.error(f"Error getting request: {str(e)}")
        return jsonify({"error": "Failed to get request"}), 500

@app.route('/get_my_requests', methods=['GET'])
def get_my_requests():
    try:
        uuid = str(request.args.get('uuid', ''))
        if not uuid:
            return jsonify({"error": "Missing required fields"}), 400
            
        # Sanitize input
        uuid = sanitize_input(uuid)
        
        Users = []
        response = supabase.table('chat_request').select('*').eq('sender_uuid', uuid).execute()
        if response.data and len(response.data) > 0:
            for user in response.data:
                Users.append(user['reciever_uuid'])
                
        response = supabase.table('chat_request').select('*').eq('reciever_uuid', uuid).execute()
        if response.data and len(response.data) > 0:
            for user in response.data:
                Users.append(user['sender_uuid'])
                
        # Remove duplicates
        Users = list(set(Users))
        return jsonify({"users": Users}), 200
        
    except Exception as e:
        app.logger.error(f"Error getting my requests: {str(e)}")
        return jsonify({"error": "Failed to get requests"}), 500

@app.route('/get_received_requests', methods=['POST'])
@validate_request_json('uuid')
def get_received_requests():
    try:
        data = request.json
        uuid = data.get('uuid')
        
        response = supabase.table("User").select('id,password').eq('id', uuid).execute()
        if len(response.data) == 0:
            return jsonify({"error": "User not found"}), 404
            
        user_pass = response.data[0]['password']
        
        # Fetch requests where user is the receiver & include sender details
        response = supabase.table('chat_request') \
            .select('*, sender:User!chat_request_sender_uuid_fkey(id, name, profile_pic, email)') \
            .eq('reciever_uuid', uuid) \
            .execute()
            
        # Filter out requests with invalid signatures
        valid_requests = []
        for request_ in response.data:
            if verify_dh_params(request_, request_['signature']):
                valid_requests.append(request_)

        return jsonify({
            "requests": valid_requests,
            'password': user_pass
        }), 200

    except Exception as e:
        app.logger.error(f"Error getting received requests: {str(e)}")
        return jsonify({"error": "Failed to get received requests"}), 500

@app.route('/get_sent_requests', methods=['POST'])
@validate_request_json('uuid')
def get_sent_requests():
    try:
        data = request.json
        uuid = data.get('uuid')

        response = supabase.table("User").select('id,password').eq('id', uuid).execute()
        if len(response.data) == 0:
            return jsonify({"error": "User not found"}), 404
            
        user_pass = response.data[0]['password']
        
        response = supabase.table('chat_request') \
            .select('*, receiver:User!chat_request_reciever_uuid_fkey(id, name, profile_pic, email)') \
            .eq('sender_uuid', uuid) \
            .execute()

        # Filter out requests with invalid signatures
        valid_requests = []
        for request_ in response.data:
            if verify_dh_params(request_, request_['signature']):
                valid_requests.append(request_)
                
        # Keep only where sender uuid is the user's uuid
        valid_requests = [x for x in valid_requests if x['sender_uuid'] == uuid]

        return jsonify({
            "requests": valid_requests,
            'password': user_pass
        }), 200

    except Exception as e:
        app.logger.error(f"Error getting sent requests: {str(e)}")
        return jsonify({"error": "Failed to get sent requests"}), 500

@app.route('/delete_request', methods=['DELETE'])
def delete_request():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Missing JSON body"}), 400
            
        id = str(data.get('request_id', ''))
        if not id:
            return jsonify({"error": "Missing required fields"}), 400

        # Sanitize input
        id = sanitize_input(id)
        
        response = supabase.table('chat_request').delete().eq('id', id).execute()
        if not response.data:
            return jsonify({"error": "Request not found"}), 404
            
        return jsonify({"success": True}), 200

    except Exception as e:
        app.logger.error(f"Error deleting request: {str(e)}")
        return jsonify({"error": "Failed to delete request"}), 500

@app.route('/reject_request', methods=['PUT'])
def reject_request():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Missing JSON body"}), 400
            
        id = str(data.get('request_id', ''))
        if not id:
            return jsonify({"error": "Missing required fields"}), 400

        # Sanitize input
        id = sanitize_input(id)
        
        response = supabase.table('chat_request').update({"confirmed": 2}).eq('id', id).execute()

        if not response.data:
            return jsonify({"error": "Request not found"}), 404
            
        return jsonify({"success": True}), 200

    except Exception as e:
        app.logger.error(f"Error rejecting request: {str(e)}")
        return jsonify({"error": "Failed to reject request"}), 500

@app.route('/accept_request', methods=['POST'])
@validate_request_json('uuid', 'request_id', 'gb', 'receiver_public_key', 'password')
def accept_request():
    try:
        data = request.json
        uuid = data.get('uuid')
        request_id = data.get('request_id')  
        gb = data.get('gb')
        receiver_public_key = data.get('receiver_public_key')
        password = data.get('password')

        response = supabase.table('User').select('password,id').eq('id', uuid).execute()
        if len(response.data) == 0:
            return jsonify({"error": "User not found"}), 404
            
        user_pass = response.data[0]['password']
        
        # Verify password using bcrypt
        if not verify_password(user_pass, password):
            return jsonify({"error": "Authentication failed"}), 401
        
        response = supabase.table('chat_request').update({
            "confirmed": 1,
            "reciever_public_key": receiver_public_key,  
            "g^b": gb  
        }).eq('id', request_id).execute()

        if not response.data:
            return jsonify({"error": "Request not found"}), 404

        sender_uuid = response.data[0]['sender_uuid']
        receiver_uuid = response.data[0]['reciever_uuid']

        # Create a new chat entry
        new_chat = supabase.table('chat').insert({
            "first_part": sender_uuid,
            "second_part": receiver_uuid
        }).execute()

        if not new_chat.data:
            return jsonify({"error": "Error creating chat"}), 500

        chat_uuid = new_chat.data[0]['uuid']
        return jsonify({"chat_uuid": chat_uuid}), 200

    except Exception as e:
        app.logger.error(f"Error accepting request: {str(e)}")
        return jsonify({"error": "Failed to accept request"}), 500

@app.route('/get_chat', methods=['GET'])
def get_chat():
    try:
        chat_id = request.args.get('chat_id')
        uuid = request.args.get('uuid')  # User's UUID

        if not chat_id or not uuid:
            return jsonify({"error": "Missing required fields"}), 400

        # Sanitize inputs
        chat_id = sanitize_input(chat_id)
        uuid = sanitize_input(uuid)
        
        # Fetch chat details for the given chat_id
        response = supabase.table('chat').select('*').eq('uuid', chat_id).execute()

        if not response.data:
            return jsonify({"error": "Chat not found"}), 404

        chat = response.data[0]
        first_part = chat['first_part']
        second_part = chat['second_part']

        # Determine the other participant
        other_uuid = first_part if second_part == uuid else second_part

        # Fetch user details (name, profilePic)
        user_response = supabase.table('User').select('name, profile_pic').eq('id', other_uuid).execute()

        if not user_response.data:
            return jsonify({"error": "User not found"}), 404

        user = user_response.data[0]

        # Fetch the last message from this chat
        message_response = supabase.table('message').select('sender,content,seen, at,type') \
            .eq('chat', chat_id).order('at', desc=True).limit(1).execute()

        last_message = message_response.data[0] if message_response.data else None
        seen = False
        sender = ''

        if last_message:
            seen = True if last_message['seen'] == 1 else False
            sender = 'him' if last_message['sender'] != uuid else 'you'
            
        type = last_message['type'] if last_message else 'text'
        if type != "text":
            last_message_txt = type
        else:
            last_message_txt = last_message['content'] if last_message else "No messages yet"
            
        chat_data = {
            "sender": sender,
            "other_party": other_uuid,
            "id": chat_id,
            "name": user['name'],
            "profilePic": user['profile_pic'],
            "lastMessage": last_message_txt,
            "seen": seen if last_message else True,
            "date": last_message['at'].split("T")[1][:5] if last_message else '',
            "type": type
        }

        return jsonify({"chat": chat_data}), 200

    except Exception as e:
        app.logger.error(f"Error getting chat: {str(e)}")
        return jsonify({"error": "Failed to get chat"}), 500

@app.route('/get_chat_list', methods=['GET'])
def get_chat_list():
    try:
        uuid = request.args.get('uuid')
        if not uuid:
            return jsonify({"error": "Missing required fields"}), 400

        # Sanitize input
        uuid = sanitize_input(uuid)
        
        # Get chats where the user is either first_part or second_part
        response = supabase.table('chat').select('*').or_(
            f'first_part.eq.{uuid},second_part.eq.{uuid}'
        ).execute()

        if not response.data:
            return jsonify({"chats": []}), 200  # Return empty list if no chats found

        chat_list = []

        for chat in response.data:
            chat_uuid = chat['uuid']
            first_part = chat['first_part']
            second_part = chat['second_part']
            
            # Determine the other participant
            other_uuid = first_part if second_part == uuid else second_part

            # Fetch user details (name, profilePic)
            user_response = supabase.table('User').select('name, profile_pic').eq('id', other_uuid).execute()

            if not user_response.data:
                continue  # Skip if user not found

            user = user_response.data[0]
            
            # Fetch the last message from this chat
            message_response = supabase.table('message').select('sender,content, seen, at,type') \
                .eq('chat', chat_uuid).order('at', desc=True).limit(1).execute()

            last_message = message_response.data[0] if message_response.data else None
            seen = False
            sender = ''
            
            if last_message:
                seen = True if last_message['seen'] == 1 else False
                sender = 'him' if last_message['sender'] != uuid else 'you'
                
            type = last_message['type'] if last_message else 'text'
            if type != "text":
                last_message_txt = type
            else:
                last_message_txt = last_message['content'] if last_message else "No messages yet"
                
            chat_list.append({
                "sender": sender,
                "other_party": other_uuid,
                "id": chat_uuid,
                "name": user['name'],
                "profilePic": user['profile_pic'],
                "lastMessage": last_message_txt,
                "seen": seen if last_message else True,
                "date": last_message['at'].split("T")[1][:5] if last_message else '',
                "type": type
            })

        return jsonify({"chats": chat_list}), 200

    except Exception as e:
        app.logger.error(f"Error getting chat list: {str(e)}")
        return jsonify({"error": "Failed to get chat list"}), 500

@app.route('/get_messages', methods=['GET'])
def get_messages():
    try:
        chatid = str(request.args.get('chatid', ''))
        myuuid = str(request.args.get('uuid', ''))  # Get the receiver's UUID

        if not chatid or not myuuid:
            return jsonify({"error": "Missing required fields"}), 400

        # Sanitize inputs
        chatid = sanitize_input(chatid)
        myuuid = sanitize_input(myuuid)
        
        # Fetch messages for the given chat ID
        response = supabase.table('message').select('*').eq('chat', chatid).execute()

        if response.data:
            messages = sorted(
                response.data,
                key=lambda x: datetime.fromisoformat(x['at']) if isinstance(x['at'], str) else x['at'],
                reverse=True
            )
            # Get IDs of unseen messages from other users
            unseen_message_ids = [
                msg['id'] for msg in messages if (msg['sender'] != myuuid and msg['seen'] == 0)
            ]

            # If there are unseen messages, mark them as seen
            if unseen_message_ids:
                supabase.table('message').update({'seen': 1}).in_('id', unseen_message_ids).execute()
                for msg in messages:
                    if msg['id'] in unseen_message_ids:
                        msg['seen'] = 1  
        else:
            messages = []

        return jsonify({"messages": messages}), 200

    except Exception as e:
        app.logger.error(f"Error getting messages: {str(e)}")
        return jsonify({"error": "Failed to get messages"}), 500

@app.route('/send_message', methods=['POST'])
@validate_request_json('chat_id', 'sender', 'reciever', 'content')
def send_message():
    try:
        data = request.json
        chat_id = data.get("chat_id")
        sender = data.get("sender")
        receiver = data.get("reciever") 
        content = data.get("content")
        type = data.get('type', "text")

        message_data = {
            "chat": chat_id,
            "sender": sender,
            "reciever": receiver,
            "content": content,
            "type": type
        }
        
        response = supabase.table('message').insert(message_data).execute()

        if response.data:
            return jsonify({"message": "Message sent successfully!"}), 200
        else:
            return jsonify({"error": "Failed to store message"}), 500
            
    except Exception as e:
        app.logger.error(f"Error sending message: {str(e)}")
        return jsonify({"error": "Failed to send message"}), 500

@app.route('/finalize_pair', methods=['POST'])
@validate_request_json('uuid', 'password')
def finalize_pair():
    try:
        data = request.json
        uuid = data.get('uuid')
        password = data.get('password')

        response = supabase.table('User').select('id,password').eq('id', uuid).execute()
        if len(response.data) == 0:
            return jsonify({"error": "User not found"}), 404
            
        user_pass = response.data[0]['password']
        
        # Verify password using bcrypt
        if not verify_password(user_pass, password):
            return jsonify({"error": "Authentication failed"}), 401
            
        # Retrieve the pair record for the given UUID
        response = supabase.table('pair').select('id', 'key', 'original_public', 'signature').eq('user_id', uuid).execute()
        if len(response.data) == 0:
            return jsonify({"error": "No pair found for the given UUID"}), 404
        
        # Verify signature
        try:
            payload = jwt.decode(response.data[0]['signature'], PUBLIC_KEY, algorithms=["RS256"])
            # Verify the signature contains the correct payload if needed
        except jwt.InvalidTokenError as e:
            app.logger.error(f"Invalid token: {str(e)}")
            return jsonify({"error": "Invalid signature"}), 401
        
        # Get the pair details
        pair_data = response.data[0]
        signed_chats = pair_data.get('key')
        original_public = pair_data.get('original_public')

       # Now delete the pair record
        delete_response = supabase.table('pair').delete().eq('id', pair_data['id']).execute()

        if delete_response.data:
            return jsonify({
                "message": "Pair finalized and record deleted", 
                "key": signed_chats, 
                "original_public": original_public
            }), 200
        else:
            return jsonify({"error": "Failed to delete pair record"}), 500
            
    except Exception as e:
        app.logger.error(f"Error finalizing pair: {str(e)}")
        return jsonify({"error": "Failed to finalize pair"}), 500

@app.route('/pair', methods=['POST'])
@validate_request_json('uuid', 'signed_chats', 'original_public', 'password')
def update_pair():
    try:
        data = request.json
        uuid = data.get('uuid')
        signed_chats = data.get('signed_chats')
        original_public = data.get('original_public')
        password = data.get('password')

        response = supabase.table('User').select('id,password').eq('id', uuid).execute()
        if len(response.data) == 0:
            return jsonify({"error": "User not found"}), 404
            
        user_pass = response.data[0]['password']
        
        # Verify password using bcrypt
        if not verify_password(user_pass, password):
            return jsonify({"error": "Authentication failed"}), 401
            
        # Check if the pair with this UUID already exists
        response = supabase.table('pair').select('id').eq('user_id', uuid).execute()

        if len(response.data) > 0:
            pair_id = response.data[0]['id']
            update_response = supabase.table('pair').update({
                'key': signed_chats,
                'original_public': original_public
            }).eq('id', pair_id).execute()

            # Check if update was successful
            if update_response.data:
                return jsonify({"message": "Pair updated successfully!"}), 200
            else:
                return jsonify({"error": "Failed to update pair"}), 500
        else:
            return jsonify({"error": "No pair record found"}), 404

    except Exception as e:
        app.logger.error(f"Error updating pair: {str(e)}")
        return jsonify({"error": "Failed to update pair"}), 500

@app.route('/get_new_public', methods=['POST'])
@validate_request_json('uuid', 'password')
def get_new_public():
    try:
        data = request.json
        my_uuid = data.get('uuid')
        password = data.get('password')

        response = supabase.table('User').select('id,password').eq('id', my_uuid).execute()
        if len(response.data) == 0:
            return jsonify({"error": "User not found"}), 404
            
        user_pass = response.data[0]['password']
        
        # Verify password using bcrypt
        if not verify_password(user_pass, password):
            return jsonify({"error": "Authentication failed"}), 401
            
        response = supabase.table('pair').select('new_device_public', 'signature').eq('user_id', my_uuid).execute()
        
        if not response.data or len(response.data) == 0:
            return jsonify({"error": "No data found for the given UUID"}), 404
            
        # Verify signature if needed
        try:
            payload = jwt.decode(response.data[0]['signature'], PUBLIC_KEY, algorithms=["RS256"])
            # Additional verification if needed
        except jwt.InvalidTokenError as e:
            app.logger.error(f"Invalid token: {str(e)}")
            # Log but don't return error to avoid potential information leakage
        
        # Return the 'new_device_public' value
        new_device_public = response.data[0].get('new_device_public')
        return jsonify({"new_device_public": new_device_public}), 200
        
    except Exception as e:
        app.logger.error(f"Error getting new public key: {str(e)}")
        return jsonify({"error": "Failed to get new public key"}), 500

@app.route('/add_new_device', methods=['POST'])
@validate_request_json('uuid', 'password')
def add_new_device():
    try:
        data = request.json
        uuid = data.get('uuid')
        password = data.get('password')

        response = supabase.table('User').select('id,password').eq('id', uuid).execute()
        if len(response.data) == 0:
            return jsonify({"error": "User not found"}), 404
            
        user_pass = response.data[0]['password']
        
        # Verify password using bcrypt
        if not verify_password(user_pass, password):
            return jsonify({"error": "Authentication failed"}), 401
        
        # Sign the uuid with expiration
        signature = sign_dh_params({
            'uuid': uuid,
            'password': password  # Be careful with storing passwords in tokens
        })
        
        response = supabase.table('pair').insert({
            'user_id': uuid,
            'signature': signature
        }).execute()

        if response.data:
            # Get the id of the newly inserted pair
            inserted_pair_id = response.data[0]['id']

            # Return the id of the newly inserted pair
            return jsonify({
                "message": "Device added successfully!",
                "pair_id": inserted_pair_id
            }), 200
        else:
            return jsonify({"error": "Failed to insert data"}), 500
            
    except Exception as e:
        app.logger.error(f"Error adding new device: {str(e)}")
        return jsonify({"error": "Failed to add new device"}), 500

@app.route('/delete_pair', methods=['POST'])
@validate_request_json('pair_id')
def delete_pair():
    try:
        data = request.json
        pair_id = data.get('pair_id')

        # Sanitize input
        pair_id = sanitize_input(pair_id)
        
        response = supabase.table('pair').delete().eq('id', pair_id).execute()
 
        if response.data:
            return jsonify({"message": "Pair deleted successfully!"}), 200
        else:
            return jsonify({"error": "Failed to delete pair"}), 500
            
    except Exception as e:
        app.logger.error(f"Error deleting pair: {str(e)}")
        return jsonify({"error": "Failed to delete pair"}), 500

@app.route('/check_if_exist', methods=['GET'])
def check_if_exist():
    try:
        uuid = request.args.get('uuid')
        
        if not uuid:
            return jsonify({"error": "UUID is required"}), 400

        # Sanitize input
        uuid = sanitize_input(uuid)
        
        # Query the 'chat' table to check if the UUID is present as either 'first_part' or 'second_part'
        response = supabase.table('chat').select('uuid').or_(
            f'first_part.eq.{uuid},second_part.eq.{uuid}'
        ).execute()

        # Check if the UUID exists in chat table
        if response.data and len(response.data) > 0:
            return jsonify({
                "message": "UUID found in chat table!",
                'exist': True
            }), 200
        else:
            return jsonify({
                "message": "UUID not found in chat table.",
                'exist': False
            }), 200

    except Exception as e:
        app.logger.error(f"Error checking if exists: {str(e)}")
        return jsonify({"error": "Failed to check existence"}), 500

@app.route('/update_new_device', methods=['POST'])
@validate_request_json('uuid', 'public_key', 'password')
def update_new_device():
    try:
        data = request.json
        uuid = data.get('uuid')
        public_key = data.get('public_key')
        password = data.get('password')

        response = supabase.table('User').select('id,password').eq('id', uuid).execute()
        if len(response.data) == 0:
            return jsonify({"error": "User not found"}), 404
            
        user_pass = response.data[0]['password']
        
        # Verify password using bcrypt
        if not verify_password(user_pass, password):
            return jsonify({"error": "Authentication failed"}), 401
            
        # Sign the password for verification
        signature = sign_dh_params({'password': password})
        
        # Update the new_device_public field in the pair table for the given uuid
        response = supabase.table('pair').update({
            'new_device_public': public_key,
            'signature': signature
        }).eq('user_id', uuid).execute()

        if response.data:
            return jsonify({"message": "Public key updated successfully"}), 200
        else:
            return jsonify({"error": "Failed to update public key"}), 500
            
    except Exception as e:
        app.logger.error(f"Error updating new device: {str(e)}")
        return jsonify({"error": "Failed to update new device"}), 500

# Implementation for secure AES-GCM encryption helpers
class SecureEncryption:
    @staticmethod
    def encrypt(data, key):
        """Encrypt data using AES-GCM with random nonce"""
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        # Generate a random 12-byte nonce
        nonce = os.urandom(12)
        
        # Create AES-GCM cipher
        aesgcm = AESGCM(key)
        
        # Encrypt the data
        ciphertext = aesgcm.encrypt(nonce, data, None)
        
        # Combine nonce and ciphertext for storage/transmission
        result = base64.b64encode(nonce + ciphertext).decode('utf-8')
        return result
        
    @staticmethod
    def decrypt(encrypted_data, key):
        """Decrypt data encrypted with AES-GCM"""
        # Decode from base64
        data = base64.b64decode(encrypted_data)
        
        # Extract nonce and ciphertext
        nonce = data[:12]
        ciphertext = data[12:]
        
        # Create AES-GCM cipher
        aesgcm = AESGCM(key)
        
        # Decrypt the data
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode('utf-8')
        except Exception as e:
            app.logger.error(f"Decryption error: {str(e)}")
            return None

if __name__ == "__main__":
    # Check if running in production
    if os.getenv('FLASK_ENV') == 'production':
        # Production settings
        from waitress import serve
        serve(app, host="0.0.0.0", port=int(os.getenv('PORT', 5000)))
    else:
        # Development settings
        app.run(host="0.0.0.0", port=int(os.getenv('PORT', 5000)), debug=False)