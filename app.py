from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import os
import random
import string
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import re
from dotenv import load_dotenv
import eventlet

eventlet.monkey_patch()

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', os.urandom(24).hex())
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///chat.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*")
CORS(app)

if not app.debug:
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/chat_app.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Chat app startup')

class Room(db.Model):
    id = db.Column(db.String(16), primary_key=True)
    password_hash = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    host_sid = db.Column(db.String(50))
    is_persistent = db.Column(db.Boolean, default=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.String(16), db.ForeignKey('room.id'))
    username = db.Column(db.String(20))
    content = db.Column(db.Text)
    encrypted = db.Column(db.Boolean, default=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    recipient = db.Column(db.String(20), nullable=True)
    file_data = db.Column(db.Text, nullable=True)
    file_type = db.Column(db.String(50), nullable=True)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20))
    room_id = db.Column(db.String(16), db.ForeignKey('room.id'))
    socket_id = db.Column(db.String(50))
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_muted = db.Column(db.Boolean, default=False)
    volume_level = db.Column(db.Integer, default=100)
    avatar = db.Column(db.String(200), default='https://via.placeholder.com/40')
    color = db.Column(db.String(7), default='#000000')
    is_moderator = db.Column(db.Boolean, default=False)
    in_voice_chat = db.Column(db.Boolean, default=False)

class Ban(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.String(16), db.ForeignKey('room.id'))
    username = db.Column(db.String(20))
    banned_at = db.Column(db.DateTime, default=datetime.utcnow)

class Reaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('message.id'))
    username = db.Column(db.String(20))
    emoji = db.Column(db.String(10))

with app.app_context():
    db.create_all()

def get_or_create_key():
    key_file = "chat_key.key"
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(key)
        return key

encryption_key = get_or_create_key()
cipher = Fernet(encryption_key)

def encrypt_message(message):
    return cipher.encrypt(message.encode()).decode()

def decrypt_message(encrypted_message):
    return cipher.decrypt(encrypted_message.encode()).decode()

def validate_username(username):
    return 1 <= len(username) <= 20 and re.match(r'^[a-zA-Z0-9_]+$', username)

def validate_password(password):
    return password and 4 <= len(password) <= 100

def sanitize_input(input_string):
    return re.sub(r'[<>"\']', '', input_string)

def generate_secure_room_id():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16))

@app.route('/')
def index():
    room_id = generate_secure_room_id()
    new_room = Room(id=room_id, host_sid=None)
    db.session.add(new_room)
    db.session.commit()
    return render_template('index.html', room_id=room_id)

@app.route('/api/rooms/new', methods=['POST'])
def create_room():
    room_id = generate_secure_room_id()
    new_room = Room(id=room_id, host_sid=None)
    db.session.add(new_room)
    db.session.commit()
    return jsonify({'room_id': room_id})

@app.route('/api/rooms/<room_id>/users')
def get_room_users(room_id):
    users = User.query.filter_by(room_id=room_id).all()
    return jsonify({
        'users': [{'username': user.username, 'is_muted': user.is_muted, 'avatar': user.avatar, 'color': user.color, 'is_moderator': user.is_moderator, 'in_voice_chat': user.in_voice_chat} for user in users],
        'count': len(users),
        'is_host': False
    })

@socketio.on('join_room')
def handle_join_room(data):
    try:
        room_id = data.get('room_id')
        password = data.get('password', '')
        username = sanitize_input(data.get('username', '').strip())
        avatar = data.get('avatar', 'https://via.placeholder.com/40')
        color = data.get('color', '#000000')
        
        if not room_id or not validate_username(username):
            emit('error', {'message': 'Invalid room ID or username'})
            return
            
        room = db.session.get(Room, room_id)
        if not room:
            emit('error', {'message': 'Room not found'})
            return
            
        if room.password_hash and not check_password_hash(room.password_hash, password):
            emit('error', {'message': 'Incorrect password'})
            return
            
        if Ban.query.filter_by(room_id=room_id, username=username).first():
            emit('error', {'message': 'You are banned from this room'})
            return
            
        if User.query.filter_by(room_id=room_id, username=username).first():
            emit('error', {'message': 'Username already taken'})
            return
            
        is_host = not room.host_sid
        if is_host:
            room.host_sid = request.sid
            db.session.commit()
            
        join_room(room_id)
        
        new_user = User(username=username, room_id=room_id, socket_id=request.sid, avatar=avatar, color=color)
        db.session.add(new_user)
        db.session.commit()
        
        emit('user_joined', {
            'username': username,
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'user_count': User.query.filter_by(room_id=room_id).count()
        }, room=room_id, broadcast=True)
        
        messages = Message.query.filter_by(room_id=room_id).order_by(Message.timestamp.asc()).all()
        history = []
        for msg in messages:
            content = decrypt_message(msg.content) if msg.encrypted else msg.content
            history.append({
                'username': msg.username,
                'message': content,
                'timestamp': msg.timestamp.strftime('%H:%M:%S'),
                'recipient': msg.recipient,
                'file_data': msg.file_data,
                'file_type': msg.file_type,
                'reactions': [{'username': r.username, 'emoji': r.emoji} for r in Reaction.query.filter_by(message_id=msg.id).all()]
            })
        
        emit('join_success', {
            'message': f'Welcome to room {room_id}, {username}!',
            'room_id': room_id,
            'is_host': is_host,
            'history': history
        })
        
    except Exception as e:
        app.logger.error(f'Error in join_room: {str(e)}')
        emit('error', {'message': 'Server error'})

@socketio.on('set_password')
def handle_set_password(data):
    try:
        room = db.session.get(Room, data.get('room_id'))
        if not room or room.host_sid != request.sid:
            emit('error', {'message': 'Only host can set password'})
            return
        password = data.get('password')
        if password and not validate_password(password):
            emit('error', {'message': 'Password must be at least 4 characters'})
            return
        room.password_hash = generate_password_hash(password) if password else None
        db.session.commit()
        emit('password_set', {'message': 'Room password set successfully'})
    except Exception as e:
        app.logger.error(f'Error in set_password: {str(e)}')
        emit('error', {'message': 'Server error'})

@socketio.on('send_message')
def handle_message(data):
    try:
        room_id = data.get('room_id')
        username = data.get('username')
        message_content = sanitize_input(data.get('message', ''))
        recipient = data.get('recipient')
        
        if not room_id or not username or not message_content:
            emit('error', {'message': 'Missing required data'})
            return
            
        user = User.query.filter_by(room_id=room_id, username=username).first()
        if not user:
            emit('error', {'message': 'User not found'})
            return
            
        encrypted_content = encrypt_message(message_content)
        new_message = Message(room_id=room_id, username=username, content=encrypted_content, recipient=recipient)
        db.session.add(new_message)
        db.session.commit()
        
        timestamp = datetime.now().strftime('%H:%M:%S')
        msg_data = {
            'username': username,
            'message': message_content,
            'timestamp': timestamp,
            'message_id': new_message.id,
            'reactions': []
        }
        
        if recipient:
            recipient_user = User.query.filter_by(room_id=room_id, username=recipient).first()
            if not recipient_user:
                emit('error', {'message': 'Recipient not found'})
                return
            emit('private_message', {**msg_data, 'recipient': recipient}, to=[user.socket_id, recipient_user.socket_id])
        else:
            emit('new_message', msg_data, room=room_id, broadcast=True)
        
    except Exception as e:
        app.logger.error(f'Error in send_message: {str(e)}')
        emit('error', {'message': 'Server error'})

@socketio.on('start_voice_chat')
def handle_start_voice_chat(data):
    try:
        room_id = data.get('room_id')
        username = data.get('username')
        user = User.query.filter_by(room_id=room_id, username=username).first()
        if not user:
            emit('error', {'message': 'User not found'})
            return
        if user.is_muted:
            emit('error', {'message': 'You are muted and cannot start voice chat'})
            return
        user.in_voice_chat = True
        db.session.commit()
        emit('voice_chat_started', {
            'username': username,
            'message': f'{username} has started voice chat',
            'timestamp': datetime.now().strftime('%H:%M:%S')
        }, room=room_id, broadcast=True)
    except Exception as e:
        app.logger.error(f'Error in start_voice_chat: {str(e)}')
        emit('error', {'message': 'Server error'})

@socketio.on('end_voice_chat')
def handle_end_voice_chat(data):
    try:
        room_id = data.get('room_id')
        username = data.get('username')
        user = User.query.filter_by(room_id=room_id, username=username).first()
        if not user:
            emit('error', {'message': 'User not found'})
            return
        user.in_voice_chat = False
        db.session.commit()
        emit('voice_chat_ended', {
            'username': username,
            'message': f'{username} has ended voice chat',
            'timestamp': datetime.now().strftime('%H:%M:%S')
        }, room=room_id, broadcast=True)
    except Exception as e:
        app.logger.error(f'Error in end_voice_chat: {str(e)}')
        emit('error', {'message': 'Server error'})

@socketio.on('voice_signal')
def handle_voice_signal(data):
    try:
        room_id = data.get('room_id')
        username = data.get('username')
        signal = data.get('signal')
        user = User.query.filter_by(room_id=room_id, username=username).first()
        if not user or not user.in_voice_chat or user.is_muted:
            return
        emit('voice_signal', {
            'username': username,
            'signal': signal,
            'from_sid': request.sid
        }, room=room_id, skip_sid=request.sid)
    except Exception as e:
        app.logger.error(f'Error in voice_signal: {str(e)}')
        emit('error', {'message': 'Server error'})

@socketio.on('end_room')
def handle_end_room(data):
    try:
        room = db.session.get(Room, data.get('room_id'))
        if not room or room.host_sid != request.sid:
            emit('error', {'message': 'Only host can end room'})
            return
        
        # Fetch message IDs for reactions deletion
        message_ids = [msg.id for msg in Message.query.filter_by(room_id=room.id).all()]
        
        # Delete all associated data
        User.query.filter_by(room_id=room.id).delete()
        Message.query.filter_by(room_id=room.id).delete()
        Ban.query.filter_by(room_id=room.id).delete()
        if message_ids:
            Reaction.query.filter(Reaction.message_id.in_(message_ids)).delete(synchronize_session=False)
        db.session.delete(room)
        db.session.commit()
        
        emit('room_ended', {
            'message': 'Room ended by host and all data deleted',
            'timestamp': datetime.now().strftime('%H:%M:%S')
        }, room=room.id, broadcast=True)
    except Exception as e:
        app.logger.error(f'Error in end_room: {str(e)}')
        emit('error', {'message': 'Server error'})

@socketio.on('mute_all')
def handle_mute_all(data):
    try:
        room = db.session.get(Room, data.get('room_id'))
        if not room or (room.host_sid != request.sid and not User.query.filter_by(socket_id=request.sid, is_moderator=True).first()):
            emit('error', {'message': 'Unauthorized'})
            return
        for user in User.query.filter_by(room_id=room.id).all():
            user.is_muted = True
            user.in_voice_chat = False
        db.session.commit()
        emit('all_muted', {'message': 'All users muted', 'timestamp': datetime.now().strftime('%H:%M:%S')}, room=room.id, broadcast=True)
    except Exception as e:
        app.logger.error(f'Error in mute_all: {str(e)}')
        emit('error', {'message': 'Server error'})

@socketio.on('unmute_all')
def handle_unmute_all(data):
    try:
        room = db.session.get(Room, data.get('room_id'))
        if not room or (room.host_sid != request.sid and not User.query.filter_by(socket_id=request.sid, is_moderator=True).first()):
            emit('error', {'message': 'Unauthorized'})
            return
        for user in User.query.filter_by(room_id=room.id).all():
            user.is_muted = False
        db.session.commit()
        emit('all_unmuted', {'message': 'All users unmuted', 'timestamp': datetime.now().strftime('%H:%M:%S')}, room=room.id, broadcast=True)
    except Exception as e:
        app.logger.error(f'Error in unmute_all: {str(e)}')
        emit('error', {'message': 'Server error'})

@socketio.on('host_mute_user')
def handle_host_mute_user(data):
    try:
        room = db.session.get(Room, data.get('room_id'))
        user = User.query.filter_by(room_id=data.get('room_id'), username=data.get('username')).first()
        if not room or not user or (room.host_sid != request.sid and not User.query.filter_by(socket_id=request.sid, is_moderator=True).first()):
            emit('error', {'message': 'Unauthorized or user not found'})
            return
        user.is_muted = data.get('mute', True)
        if user.is_muted:
            user.in_voice_chat = False
        db.session.commit()
        emit('user_muted', {
            'username': user.username,
            'muted': user.is_muted,
            'message': f'{user.username} has been {"muted" if user.is_muted else "unmuted"}'
        }, room=room.id, broadcast=True)
    except Exception as e:
        app.logger.error(f'Error in host_mute_user: {str(e)}')
        emit('error', {'message': 'Server error'})

@socketio.on('kick_user')
def handle_kick_user(data):
    try:
        room = db.session.get(Room, data.get('room_id'))
        user = User.query.filter_by(room_id=data.get('room_id'), username=data.get('username')).first()
        if not room or not user or (room.host_sid != request.sid and not User.query.filter_by(socket_id=request.sid, is_moderator=True).first()):
            emit('error', {'message': 'Unauthorized or user not found'})
            return
        db.session.delete(user)
        db.session.commit()
        emit('user_kicked', {
            'username': user.username,
            'message': f'{user.username} has been kicked',
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'user_count': User.query.filter_by(room_id=room.id).count()
        }, room=room.id, broadcast=True)
        emit('force_disconnect', {'message': 'You have been kicked'}, to=user.socket_id)
    except Exception as e:
        app.logger.error(f'Error in kick_user: {str(e)}')
        emit('error', {'message': 'Server error'})

@socketio.on('ban_user')
def handle_ban_user(data):
    try:
        room = db.session.get(Room, data.get('room_id'))
        user = User.query.filter_by(room_id=data.get('room_id'), username=data.get('username')).first()
        if not room or not user or room.host_sid != request.sid:
            emit('error', {'message': 'Only host can ban users'})
            return
        ban = Ban(room_id=room.id, username=user.username)
        db.session.add(ban)
        db.session.delete(user)
        db.session.commit()
        emit('user_banned', {
            'username': user.username,
            'message': f'{user.username} has been banned',
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'user_count': User.query.filter_by(room_id=room.id).count()
        }, room=room.id, broadcast=True)
        emit('force_disconnect', {'message': 'You have been banned'}, to=user.socket_id)
    except Exception as e:
        app.logger.error(f'Error in ban_user: {str(e)}')
        emit('error', {'message': 'Server error'})

@socketio.on('promote_moderator')
def handle_promote_moderator(data):
    try:
        room = db.session.get(Room, data.get('room_id'))
        user = User.query.filter_by(room_id=data.get('room_id'), username=data.get('username')).first()
        if not room or not user or room.host_sid != request.sid:
            emit('error', {'message': 'Only host can promote moderators'})
            return
        user.is_moderator = True
        db.session.commit()
        emit('moderator_promoted', {
            'username': user.username,
            'message': f'{user.username} is now a moderator',
            'timestamp': datetime.now().strftime('%H:%M:%S')
        }, room=room.id, broadcast=True)
    except Exception as e:
        app.logger.error(f'Error in promote_moderator: {str(e)}')
        emit('error', {'message': 'Server error'})

@socketio.on('user_typing')
def handle_user_typing(data):
    try:
        user = User.query.filter_by(room_id=data.get('room_id'), username=data.get('username')).first()
        if user:
            emit('user_typing', {'username': user.username}, room=data.get('room_id'), skip_sid=request.sid)
    except Exception as e:
        app.logger.error(f'Error in user_typing: {str(e)}')
        emit('error', {'message': 'Server error'})

@socketio.on('adjust_volume')
def handle_adjust_volume(data):
    try:
        user = User.query.filter_by(room_id=data.get('room_id'), username=data.get('username')).first()
        if user and 0 <= data.get('volume', 100) <= 100:
            user.volume_level = data.get('volume')
            db.session.commit()
            emit('volume_adjusted', {'username': user.username, 'volume': user.volume_level}, room=data.get('room_id'), broadcast=True)
    except Exception as e:
        app.logger.error(f'Error in adjust_volume: {str(e)}')
        emit('error', {'message': 'Server error'})

@socketio.on('disconnect')
def handle_disconnect():
    try:
        user = User.query.filter_by(socket_id=request.sid).first()
        if user:
            room_id = user.room_id
            db.session.delete(user)
            db.session.commit()
            emit('user_left', {
                'username': user.username,
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'user_count': User.query.filter_by(room_id=room_id).count()
            }, room=room_id, broadcast=True)
            room = db.session.get(Room, room_id)
            if room and room.host_sid == request.sid and User.query.filter_by(room_id=room_id).count() == 0:
                message_ids = [msg.id for msg in Message.query.filter_by(room_id=room.id).all()]
                User.query.filter_by(room_id=room.id).delete()
                Message.query.filter_by(room_id=room.id).delete()
                Ban.query.filter_by(room_id=room.id).delete()
                if message_ids:
                    Reaction.query.filter(Reaction.message_id.in_(message_ids)).delete(synchronize_session=False)
                db.session.delete(room)
                db.session.commit()
    except Exception as e:
        app.logger.error(f'Error in disconnect: {str(e)}')

@app.errorhandler(404)
def not_found_error(error):
    return jsonify({'error': 'Not found', 'message': str(error)}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Server error', 'message': str(error)}), 500

if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=True)