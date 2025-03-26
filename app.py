
from datetime import datetime
import re
from flask import Flask, redirect, request, jsonify
from flask_mail import Mail, Message
import random
import os
import jwt
from supabase import create_client, Client
import firebase_admin
from firebase_admin import credentials, messaging
from flask_talisman import Talisman
# Initialize Firebase Admin SDK
cred = credentials.Certificate('telecrypt-8ffd5-firebase-adminsdk-fbsvc-80b35fc77b.json')
firebase_admin.initialize_app(cred)

# Function to send a notification
def send_fcm_notification(fcm_token, message):
    # Create the message notification
    message = messaging.Message(
        notification=messaging.Notification(
            title='New Message',
            body=message,
        ),
        token=fcm_token,
    )

    # Send the notification
    response = messaging.send(message)
    print('Successfully sent message:', response)

app = Flask(__name__)
# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Change for other providers
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'iheb.dia.el.hak.mekideche@ensia.edu.dz'
app.config['MAIL_PASSWORD'] = 'bvxu qixh jbhx vyxa'
app.config['MAIL_DEFAULT_SENDER'] = 'iheb.dia.el.hak.mekideche@ensia.edu.dz'

mail = Mail(app)

# Supabase Configuration
SUPABASE_URL = "https://iqehedvsmmdnslwvfzjt.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImlxZWhlZHZzbW1kbnNsd3Zmemp0Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDI3MjUwMDcsImV4cCI6MjA1ODMwMTAwN30.enGqSaf8k7cOegez0ew1l0duNBylpsAQ4erdo4fUiuc"
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)



# Load private key
with open("server_private.pem", "rb") as f:
    PRIVATE_KEY = f.read()

def sign_dh_params(payload):

    signature = jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")
    return signature




with open("server_public.pem", "rb") as f:
    PUBLIC_KEY = f.read()

def verify_dh_params(request, signature):
    try:
        payload = jwt.decode(signature, PUBLIC_KEY, algorithms=["RS256"])
        return (
            payload["g"] == request["g"]
            and payload["m"] == request["m"]
            and payload["g^a"] == request["g^a"]
            and payload["sender_uuid"] == request["sender_uuid"]
            and payload["sender_public_key"] == request["sender_public_key"]
            and payload["reciever_uuid"] == request["reciever_uuid"]
        )
    except jwt.exceptions.InvalidSignatureError:
        return False
    

# @app.before_request
# def enforce_https():
#     if not request.is_secure:
#         return redirect(request.url.replace("http://", "https://"), code=301)
    
    
    
@app.route('/send_otp', methods=['POST'])
def send_otp():
    data = request.json
    email = data.get('email')

    if not email:
        return jsonify({'error': 'Email is required'}), 400

    otp = str(random.randint(100000, 999999))
    response=None
    while response is None:
        response = supabase.table("otp").insert({"email": email, "otp": otp}).execute()

    # Send OTP Email
    msg = Message('Your OTP Code', recipients=[email])
    msg.body = f'Your OTP code is: {otp}'
    mail.send(msg)

    return jsonify({'message': 'OTP sent successfully'})

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    data = request.json
    email = data['email']
    otp = data['otp']

    if not email or not otp:
        return jsonify({'error': 'Email and OTP are required'}), 400

    # Check OTP from Supabase
    response = supabase.table("otp").select("otp").eq("email", email).execute()
    if not response:
        return jsonify({'error': 'Invalid OTP'}), 400

    stored_otp = response.data[0]["otp"]

    if stored_otp == otp:
        # Delete OTP after successful verification
        supabase.table("otp").delete().eq("email", email).execute()
        return jsonify({'message': 'OTP verified successfully'})

    return jsonify({'error': 'Invalid OTP'}), 400



















@app.route('/insert_user', methods=['POST'])
def insert_user():
    try:
        data = request.json

        username = data.get('name')
        email = data.get('email')
        password = data.get('password')  # Should already be hashed from frontend
        bio = data.get('bio', "")
        dob = data.get('dob', "")
        profile_pic_url = data.get('profile_pic', "")

        if not username or not email or not password:
            return jsonify({"error": "Missing required fields"}), 400

        # Insert User Data into Supabase
        response = supabase.table('User').insert({
            "name": username,
            "email": email,
            "password": password,
            "bio": bio,
            "birth_date": dob,
            "profile_pic": profile_pic_url
        }).execute()

        # Check for insertion errors
        if "error" in response and response["error"]:
            return jsonify({"error": response["error"]["message"]}), 500

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
        return jsonify({"error": str(e)}), 500
    
    
    
    
    
    
@app.route('/verify_email', methods=['POST'])
def verify_email():
    try:
        data = request.json
        email = data.get('email')
        if not email:
            return jsonify({"error": "Email is required"}), 400

        response = supabase.table('User').select('email').eq('email', email).execute()
        if response.data and len(response.data) > 0:
            return jsonify({"exists": True}), 201
        else:
            return jsonify({"exists": False}), 201        

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
    
    
    
    
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        if not email or not password:
            return jsonify({"error": "Missing required fields"}), 400
        response = supabase.table('User').select('*').eq('email', email).execute()
        if response.data and len(response.data) > 0:
            user = response.data[0]
            
            if user['password'] == password:
                return jsonify({"message": "Login successful", "user": user}), 200
            else:
                return jsonify({"error": "Invalid password"}), 400
        else:
            return jsonify({"error": "Invalid email or password"}), 400

    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route('/create_chat', methods=['POST'])
def create_chat():
    try:
        data = request.json
        
        sender_uuid = data.get('uuid')
        g = data.get('g')
        p = data.get('p')
        ga = data.get('ga')
        public_key = data.get('public_key')
        reciever_uuid = data.get('reciever_uuid')
        password=data.get('password')
        
        if not sender_uuid or not g or not p or not ga or not public_key or not reciever_uuid or not password:
            return jsonify({"error": "Missing required fields"}), 400
        response = supabase.table('User').select('password,id').eq('id', sender_uuid).execute()
        if len(response.data)==0:
            return jsonify({"error": "User not found"}), 400
        user_pass=response.data[0]['password']
        if not user_pass==password:
            return jsonify({"error": "Incorrect password"}), 400
        signature = sign_dh_params({
            "sender_uuid": sender_uuid,
            "g": g,
            "m": p,
            "g^a": ga,
            "sender_public_key": public_key,
            "reciever_uuid": reciever_uuid
        })
        response = supabase.table('chat_request').insert({
            "sender_uuid": sender_uuid,
            "g": g,
            "m": p,
            "g^a": ga,
            "sender_public_key": public_key,
            "reciever_uuid": reciever_uuid,
            'signature':signature
        }).execute()
        if response.data:
            return jsonify({"uuid": response.data[0]['id']}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
    
    
    
    
    
    
    
    
    
    
    
@app.route('/get_users', methods=['GET'])
def get_users():
    try:
        word = str(request.args.get('word'))
        if not word:
            return jsonify({"error": "Missing required fields"}), 400
        safe_word = re.escape(word)
        response = supabase.rpc("search_users_by_name_or_email", {"prefix": safe_word}).execute()
        Users=[]
        if response.data and len(response.data) > 0:
            for user in response.data:
                Users.append(user)
        return jsonify({"users": Users}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

@app.route('/get_request', methods=['GET'])
def get_request():
    try:
        request_id = str(request.args.get('uuid'))
        if not request_id:
            return jsonify({"error": "Missing required fields"}), 400
        response = supabase.from_("chat_request").select("*").eq("id", request_id).execute()
        if response.data and len(response.data) > 0:
            return jsonify({"request": response.data[0]}), 200
        else:
            return jsonify({"error": "Request not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
    


@app.route('/get_my_requests', methods=['GET'])
def get_my_requests():
    try:
        uuid = str(request.args.get('uuid'))
        if not uuid:
            return jsonify({"error": "Missing required fields"}), 400
        Users=[]
        response = supabase.table('chat_request').select('*').eq('sender_uuid', uuid).execute()
        if response.data and len(response.data) > 0:
            for user in response.data:
                Users.append(user['reciever_uuid'])
        response = supabase.table('chat_request').select('*').eq('reciever_uuid', uuid).execute()
        if response.data and len(response.data) > 0:
            for user in response.data:
                Users.append(user['sender_uuid'])
        # remove duplicates
        Users = list(set(Users))
        return jsonify({"users": Users}), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
    


@app.route('/get_received_requests', methods=['POST'])
def get_received_requests():
    try:
        data = request.json
        uuid = data.get('uuid')
        if not uuid:
            return jsonify({"error": "Missing required fields"}), 400
        response = supabase.table("User").select('id,password').eq('id', uuid).execute()
        if len(response.data)==0:
            return jsonify({"error": "User not found"}), 400
        user_pass=response.data[0]['password']
        # Fetch requests where user is the receiver & include sender details
        response = supabase.table('chat_request') \
            .select('*, sender:User!chat_request_sender_uuid_fkey(id, name, profile_pic, email)') \
            .eq('reciever_uuid', uuid) \
            .execute()
        for request_ in response.data:
            if not verify_dh_params(request_, request_['signature']):
                response.data.remove(request_)

        return jsonify({"requests": response.data or [],
                        'password':user_pass}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


    
    
    
    
@app.route('/get_sent_requests', methods=['POST'])
def get_sent_requests():
    try:
        data = request.json
        print(data)
        uuid = data.get('uuid')
        if not uuid:
            return jsonify({"error": "Missing required fields"}), 400

        response = supabase.table("User").select('id,password').eq('id', uuid).execute()
        if len(response.data)==0:
            return jsonify({"error": "User not found"}), 400
        user_pass=response.data[0]['password']
        response = supabase.table('chat_request') \
            .select('*, receiver:User!chat_request_reciever_uuid_fkey(id, name, profile_pic, email)') \
            .eq('sender_uuid', uuid) \
            .execute()

        for request_ in response.data:
            if not verify_dh_params(request_, request_['signature']):
                response.data.remove(request_)
        # keep only where sender uuid is not my uuid
        response.data = [x for x in response.data if x['sender_uuid'] == uuid]

        return jsonify({"requests": response.data or [],
                        'password':user_pass}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500











@app.route('/delete_request', methods=['DELETE'])
def delete_request():
    try:
        id = str(request.json.get('request_id'))
        if not id:
            return jsonify({"error": "Missing required fields"}), 400

        response = supabase.table('chat_request').delete().eq('id', id).execute()
        if response.data == 0:
            return jsonify({"error": "Request not found"}), 404
        return jsonify({"success": True}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
    

@app.route('/reject_request', methods=['PUT'])
def reject_request():
    try:
        
        id = str(request.json.get('request_id'))
        if not id:
            return jsonify({"error": "Missing required fields"}), 400

        response = supabase.table('chat_request').update({"confirmed": 2}).eq('id', id).execute()

        if response.data == 0:
            return jsonify({"error": "Request not found"}), 404
        return jsonify({"success": True}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    







@app.route('/accept_request', methods=['POST'])
def accept_request():
    try:
        
        data = request.json
        uuid = data.get('uuid')
        request_id = data.get('request_id')  
        gb = data.get('gb')
        receiver_public_key = data.get('receiver_public_key')
        password = data.get('password')

        if not request_id or not gb or not receiver_public_key or not password:
            return jsonify({"error": "Missing required fields"}), 400


        response =supabase.table('User').select('password,id').eq('id', uuid).execute()
        if len(response.data)==0:
            return jsonify({"error": "User not found"}), 400
        user_pass=response.data[0]['password']
        if not user_pass==password:
            return jsonify({"error": "Incorrect password"}), 400
        
        
        response = supabase.table('chat_request').update({
            "confirmed": 1,
            "reciever_public_key": receiver_public_key,  
            "g^b": gb  
        }).eq('id', request_id).execute()

        if not response.data:  # Corrected condition
            return jsonify({"error": "Request not found"}), 404

        sender_uuid = response.data[0]['sender_uuid']
        receiver_uuid = response.data[0]['reciever_uuid']

        # Create a new chat entry
        new_chat = supabase.table('chat').insert({
            "first_part": sender_uuid,
            "second_part": receiver_uuid
        }).execute()

        if not new_chat.data:  # Corrected condition
            return jsonify({"error": "Error creating chat"}), 500

        chat_uuid = new_chat.data[0]['uuid']
        return jsonify({"chat_uuid": chat_uuid}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500















@app.route('/get_chat', methods=['GET'])
def get_chat():
    try:
        chat_id = request.args.get('chat_id')
        uuid = request.args.get('uuid')  # User's UUID

        if not chat_id or not uuid:
            return jsonify({"error": "Missing required fields"}), 400

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
        message_response = supabase.table('message').select('sender,content,seen, at') \
            .eq('chat', chat_id).order('at', desc=True).limit(1).execute()

        last_message = message_response.data[0] if message_response.data else None
        seen = False
        sender = ''

        if last_message:
            seen = True if last_message['seen'] == 1 else False
            sender = 'him' if last_message['sender'] != uuid else 'you'

        chat_data = {
            "sender": sender,
            "other_party": other_uuid,
            "id": chat_id,
            "name": user['name'],
            "profilePic": user['profile_pic'],
            "lastMessage": last_message['content'] if last_message else "No messages yet",
            "seen": seen if last_message else True,
            "date": last_message['at'].split("T")[1][:5] if last_message else ''
        }

        return jsonify({"chat": chat_data}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500










@app.route('/get_chat_list', methods=['GET'])
def get_chat_list():
    try:
        uuid = request.args.get('uuid')
        if not uuid:
            return jsonify({"error": "Missing required fields"}), 400

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
            message_response = supabase.table('message').select('sender,content, seen, at') \
                .eq('chat', chat_uuid).order('at', desc=True).limit(1).execute()

            last_message = message_response.data[0] if message_response.data else None
            seen=False

            sender=''
            if last_message:
                seen=True if last_message['seen']==1 else False
                if last_message['sender']!=uuid:
                    sender='him'
                else:
                    sender='you'
            chat_list.append({
                "sender":sender,
                "other_party":other_uuid,
                "id" : chat_uuid,
                "name": user['name'],
                "profilePic": user['profile_pic'],
                "lastMessage": last_message['content'] if last_message else "No messages yet",
                "seen": seen if last_message else True,
                "date": last_message['at'].split("T")[1][:5] if last_message else ''
            })

        return jsonify({"chats": chat_list}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/get_messages', methods=['GET'])
def get_messages():
    try:
        chatid = str(request.args.get('chatid'))
        myuuid = str(request.args.get('uuid'))  # Get the receiver's UUID

        if not chatid or not myuuid:
            return jsonify({"error": "Missing required fields"}), 400

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
                msg['id'] for msg in messages if (msg['sender'] != myuuid and msg['seen']==0)
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
        return jsonify({"error": str(e)}), 500




















@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.json
    chat_id = data.get("chat_id")
    sender = data.get("sender")
    receiver = data.get("reciever") 
    content = data.get("content")

    if not all([chat_id, sender, receiver, content]):
        return jsonify({"error": "Missing fields"}), 400

   

    message_data = {
        "chat": chat_id,
        "sender": sender,
        "reciever": receiver,
        "content": content
    }
    response = supabase.table('message').insert(message_data).execute()

    if response.data:
        return jsonify({"message": "Message sent successfully!"}), 200
    else:
        return jsonify({"error": "Failed to store message"}), 500























@app.route('/finalize_pair', methods=['POST'])
def finalize_pair():
    # Get the UUID from the request
    data = request.get_json()
    uuid = data.get('uuid')
    password = data.get('password')
    if not uuid:
        return jsonify({"error": "UUID is required"}), 400

    try:
        response = supabase.table('User').select('id,password').eq('id', uuid).execute()
        if len(response.data) == 0:
            return jsonify({"error": "User not found"}), 404
        user_pass=response.data[0]['password']
        if user_pass != password:
            return jsonify({"error": "Incorrect password"}), 401
        # Retrieve the pair record for the given UUID
        response = supabase.table('pair').select('id', 'key', 'original_public,signature').eq('user_id', uuid).execute()
        if len(response.data) == 0:
            return jsonify({"error": "No pair found for the given UUID"}), 404
        
        payload = jwt.decode(response.data[0]['signature'], PUBLIC_KEY, algorithms=["RS256"])
        if password!= payload['password']:
            return jsonify({"error": "Incorrect person"}), 401
        # Get the pair details
        pair_data = response.data[0]
        signed_chats = pair_data.get('key')
        original_public = pair_data.get('original_public')

        # You can perform any necessary operations with the retrieved key (e.g., return it)
        # In this case, we're just returning the original_public as 'key'
        key = original_public

       # Now delete the pair record
        delete_response = supabase.table('pair').delete().eq('id', pair_data['id']).execute()

        if delete_response.data :
            return jsonify({"message": "Pair finalized and record deleted", "key": signed_chats, "original_public": original_public}), 200
        else:
             return jsonify({"error": "Failed to delete pair record"}), 500
            #return jsonify({"message": "Pair finalized and record deleted", "key": signed_chats, "original_public": original_public}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/pair', methods=['POST'])
def update_pair():
    # Get the JSON data from the request
    data = request.get_json()
    uuid = data.get('uuid')
    signed_chats = data.get('signed_chats')
    original_public = data.get('original_public')
    password = data.get('password')
    if not uuid or not signed_chats or not original_public or not password:
        return jsonify({"error": "UUID, signed_chats, and original_public are required"}), 400

    try:
        response = supabase.table('User').select('id,password').eq('id', uuid).execute()
        if len(response.data) == 0:
            return jsonify({"error": "User not found"}), 404
        user_pass=response.data[0]['password']
        if user_pass != password:
            return jsonify({"error": "Incorrect password"}), 401
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
            
            
                return jsonify({"error": "Failed to add new pair"}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500






@app.route('/get_new_public', methods=['POST'])
def get_new_public():
    data = request.json
    my_uuid = data.get('uuid')
    password = data.get('password')

    if not my_uuid or not password:
        return jsonify({"error": "UUID is required"}), 400

    response = supabase.table('User').select('id,password').eq('id', my_uuid).execute()
    if len(response.data) == 0:
        return jsonify({"error": "User not found"}), 404
    user_pass=response.data[0]['password']
    if user_pass != password:
        return jsonify({"error": "Incorrect password"}), 401
    response = supabase.table('pair').select('new_device_public,signature').eq('user_id', my_uuid).execute()
    payload = jwt.decode(response.data[0]['signature'], PUBLIC_KEY, algorithms=["RS256"])
    if password!= payload['password']:
        return jsonify({"error": "Incorrect person"}), 401
    
    if  not response.data or len(response.data) == 0:
        return jsonify({"error": "No data found for the given UUID"}), 404

    # Return the 'new_device_public' value
    new_device_public = response.data[0].get('new_device_public')
    return jsonify({"new_device_public": new_device_public}), 200



@app.route('/add_new_device', methods=['POST'])
def add_new_device():
    # Get the UUID from the request
    data = request.get_json()
    uuid = data.get('uuid')
    password = data.get('password')
    print(data)
    if not uuid or not password:
        return jsonify({"error": "UUID is required"}), 400

    # Insert the UUID into the pair table
    try:
        response = supabase.table('User').select('id,password').eq('id', uuid).execute()
        if len(response.data) == 0:
            return jsonify({"error": "User not found"}), 404
        user_pass=response.data[0]['password']
        if user_pass != password:
            return jsonify({"error": "Incorrect password"}), 401
        
        signature = jwt.encode({'uuid':uuid}, PRIVATE_KEY, algorithm="RS256")
        response = supabase.table('pair').insert({'user_id': uuid,'signature':signature}).execute()

        # Check if the insertion was successful
        if response.data !=0:
            # Get the id of the newly inserted pair
            inserted_pair_id = response.data[0]['id']  # Assuming the id is in the returned data

            # Return the id of the newly inserted pair along with a success message
            return jsonify({
                "message": "Device added successfully!",
                "pair_id": inserted_pair_id  # Return the id of the new pair
            }), 200
        else:
            return jsonify({"error": "Failed to insert data"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/delete_pair', methods=['POST'])
def delete_pair():
    # Get the pair_id from the request
    data = request.get_json()
    pair_id = data.get('pair_id')

    if not pair_id:
        return jsonify({"error": "pair_id is required"}), 400

    try:
        # Delete from the 'pair' table using the provided pair_id
        response = supabase.table('pair').delete().eq('id', pair_id).execute()
 
        # Check if the deletion was successful
        if response.data:
            return jsonify({"message": "Pair deleted successfully!"}), 200
        else:
            return jsonify({"error": "Failed to delete pair"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route('/check_if_exist', methods=['GET'])
def check_if_exist():
    # Get the UUID from the request
    uuid = request.args.get('uuid')
    
    if not uuid:
        return jsonify({"error": "UUID is required"}), 400

    try:
        # Query the 'chat' table to check if the UUID is present as either 'first_part' or 'second_part'
        response = supabase.table('chat').select('uuid').eq('first_part', uuid).eq('second_part', uuid).execute()

        # Check if the UUID exists in either 'first_part' or 'second_part'
        if response.data:
            return jsonify({"message": "UUID found in chat table!"
                            ,'exist': True}), 200
        else:
            return jsonify({"message": "UUID not found in chat table.",
                            'exist': False}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/update_new_device', methods=['POST'])
def update_new_device():
    data = request.get_json()

    uuid = data.get('uuid')
    public_key = data.get('public_key')
    password = data.get('password')
    response = supabase.table('User').select('id,password').eq('id', uuid).execute()
    if len(response.data) == 0:
        return jsonify({"error": "User not found"}), 404
    user_pass=response.data[0]['password']
    if user_pass != password:
        return jsonify({"error": "Incorrect password"}), 401
    if not uuid or not public_key:
        return jsonify({"error": "UUID or public_key missing"}), 400
    signature = jwt.encode({'password':password}, PRIVATE_KEY, algorithm="RS256")
    # Update the new_device_public field in the pair table for the given uuid
    response = supabase.table('pair').update({
        'new_device_public': public_key,
        'signature':signature
    }).eq('user_id', uuid).execute()

    if response.data:
        return jsonify({"message": "Public key updated successfully"}), 200
    else:
        return jsonify({"error": "Failed to update public key"}), 500
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)