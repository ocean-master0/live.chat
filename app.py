# pip install Flask-SQLAlchemy
# pip install Flask-CORS
# pip install python-dotenv


from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit, join_room
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import os
import time
import random
import string
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import re
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', os.urandom(24).hex())
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///chat.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")
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
    
    def __repr__(self):
        return f'<Room {self.id}>'

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.String(16), db.ForeignKey('room.id'))
    username = db.Column(db.String(20))
    content = db.Column(db.Text)
    encrypted = db.Column(db.Boolean, default=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Message {self.id} by {self.username}>'

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20))
    room_id = db.Column(db.String(16), db.ForeignKey('room.id'))
    socket_id = db.Column(db.String(50))
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_muted = db.Column(db.Boolean, default=False)
    volume_level = db.Column(db.Integer, default=100)
    
    def __repr__(self):
        return f'<User {self.username} in {self.room_id}>'

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
    if not (1 <= len(username) <= 20 and re.match(r'^[a-zA-Z0-9_]+$', username)):
        return False
    return True

def validate_password(password):
    if not password or len(password) < 4 or len(password) > 100:
        return False
    return True

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
    room = db.session.get(Room, room_id)
    return jsonify({
        'users': [{'username': user.username, 'is_muted': user.is_muted} for user in users],
        'count': len(users),
        'is_host': False
    })

@socketio.on('join_room')
def handle_join_room(data):
    try:
        room_id = data.get('room_id')
        password = data.get('password', '')
        username = sanitize_input(data.get('username', '').strip())
        
        if not room_id:
            emit('error', {'message': 'Room ID is required'})
            return
            
        if not validate_username(username):
            emit('error', {'message': 'Username must be 1-20 alphanumeric characters'})
            return
            
        room = db.session.get(Room, room_id)
        if not room:
            emit('error', {'message': 'Room not found'})
            return
            
        if room.password_hash and not check_password_hash(room.password_hash, password):
            emit('error', {'message': 'Incorrect password'})
            return
            
        existing_user = User.query.filter_by(room_id=room_id, username=username).first()
        if existing_user:
            emit('error', {'message': 'Username already taken in this room'})
            return
            
        is_host = False
        if not room.host_sid:
            room.host_sid = request.sid
            is_host = True
            db.session.commit()
            
        join_room(room_id)
        
        new_user = User(username=username, room_id=room_id, socket_id=request.sid)
        db.session.add(new_user)
        db.session.commit()
        
        emit('user_joined', {
            'username': username,
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'user_count': User.query.filter_by(room_id=room_id).count()
        }, room=room_id, broadcast=True)
        
        emit('join_success', {
            'message': f'Welcome to room {room_id}, {username}!',
            'room_id': room_id,
            'is_host': is_host
        })
        
    except Exception as e:
        app.logger.error(f'Error in join_room: {str(e)}')
        emit('error', {'message': 'Server error while joining room'})

@socketio.on('set_password')
def handle_set_password(data):
    try:
        room_id = data.get('room_id')
        password = data.get('password')
        
        room = db.session.get(Room, room_id)
        if not room or room.host_sid != request.sid:
            emit('error', {'message': 'Only host can set password'})
            return
            
        if password and not validate_password(password):
            emit('error', {'message': 'Password must be at least 4 characters'})
            return
            
        room.password_hash = generate_password_hash(password) if password else None
        db.session.commit()
        
        emit('password_set', {'message': 'Room password set successfully'})
        
    except Exception as e:
        app.logger.error(f'Error in set_password: {str(e)}')
        emit('error', {'message': 'Server error while setting password'})

@socketio.on('send_message')
def handle_message(data):
    try:
        room_id = data.get('room_id')
        username = data.get('username')
        message_content = sanitize_input(data.get('message', ''))
        
        if not room_id or not username or not message_content:
            emit('error', {'message': 'Missing required message data'})
            return
            
        user = User.query.filter_by(room_id=room_id, username=username).first()
        if not user:
            emit('error', {'message': 'User not found in this room'})
            return
            
        encrypted_content = encrypt_message(message_content)
        
        new_message = Message(
            room_id=room_id,
            username=username,
            content=encrypted_content,
            encrypted=True,
            timestamp=datetime.now()
        )
        db.session.add(new_message)
        db.session.commit()
        
        timestamp = datetime.now().strftime('%H:%M:%S')
        emit('new_message', {
            'username': username,
            'message': message_content,
            'timestamp': timestamp,
            'message_id': new_message.id
        }, room=room_id, broadcast=True)
        
    except Exception as e:
        app.logger.error(f'Error in send_message: {str(e)}')
        emit('error', {'message': 'Server error while sending message'})

@socketio.on('end_room')
def handle_end_room(data):
    try:
        room_id = data.get('room_id')
        room = db.session.get(Room, room_id)
        
        if not room or room.host_sid != request.sid:
            emit('error', {'message': 'Only host can end the room'})
            return
            
        User.query.filter_by(room_id=room_id).delete()
        Message.query.filter_by(room_id=room_id).delete()
        db.session.delete(room)
        db.session.commit()
        
        emit('room_ended', {
            'message': 'Room has been ended by host and all data has been deleted',
            'timestamp': datetime.now().strftime('%H:%M:%S')
        }, room=room_id, broadcast=True)
        
    except Exception as e:
        app.logger.error(f'Error in end_room: {str(e)}')
        emit('error', {'message': 'Server error while ending room'})

@socketio.on('mute_all')
def handle_mute_all(data):
    try:
        room_id = data.get('room_id')
        room = db.session.get(Room, room_id)
        
        if not room or room.host_sid != request.sid:
            emit('error', {'message': 'Only host can mute all'})
            return
            
        users = User.query.filter_by(room_id=room_id).all()
        for user in users:
            user.is_muted = True
        
        db.session.commit()
        
        emit('all_muted', {
            'message': 'All users have been muted by host',
            'timestamp': datetime.now().strftime('%H:%M:%S')
        }, room=room_id, broadcast=True)
        
    except Exception as e:
        app.logger.error(f'Error in mute_all: {str(e)}')
        emit('error', {'message': 'Server error while muting all'})

@socketio.on('unmute_all')
def handle_unmute_all(data):
    try:
        room_id = data.get('room_id')
        room = db.session.get(Room, room_id)
        
        if not room or room.host_sid != request.sid:
            emit('error', {'message': 'Only host can unmute all'})
            return
            
        users = User.query.filter_by(room_id=room_id).all()
        for user in users:
            user.is_muted = False
        
        db.session.commit()
        
        emit('all_unmuted', {
            'message': 'All users have been unmuted by host',
            'timestamp': datetime.now().strftime('%H:%M:%S')
        }, room=room_id, broadcast=True)
        
    except Exception as e:
        app.logger.error(f'Error in unmute_all: {str(e)}')
        emit('error', {'message': 'Server error while unmuting all'})

@socketio.on('host_mute_user')
def handle_host_mute_user(data):
    try:
        room_id = data.get('room_id')
        username = data.get('username')
        mute_status = data.get('mute', True)
        room = db.session.get(Room, room_id)
        
        if not room or room.host_sid != request.sid:
            emit('error', {'message': 'Only host can mute/unmute users'})
            return
            
        user = User.query.filter_by(room_id=room_id, username=username).first()
        if not user:
            emit('error', {'message': 'User not found'})
            return
            
        user.is_muted = mute_status
        db.session.commit()
        
        emit('user_muted', {
            'username': username,
            'muted': mute_status,
            'message': f'{username} has been {"muted" if mute_status else "unmuted"} by host'
        }, room=room_id, broadcast=True)
        
    except Exception as e:
        app.logger.error(f'Error in host_mute_user: {str(e)}')
        emit('error', {'message': 'Server error while muting/unmuting user'})

@socketio.on('kick_user')
def handle_kick_user(data):
    try:
        room_id = data.get('room_id')
        username = data.get('username')
        room = db.session.get(Room, room_id)
        
        if not room or room.host_sid != request.sid:
            emit('error', {'message': 'Only host can kick users'})
            return
            
        user = User.query.filter_by(room_id=room_id, username=username).first()
        if not user:
            emit('error', {'message': 'User not found'})
            return
            
        db.session.delete(user)
        db.session.commit()
        
        emit('user_kicked', {
            'username': username,
            'message': f'{username} has been kicked by host',
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'user_count': User.query.filter_by(room_id=room_id).count()
        }, room=room_id, broadcast=True)
        
        emit('force_disconnect', {
            'message': 'You have been kicked from the room'
        }, to=user.socket_id)
        
    except Exception as e:
        app.logger.error(f'Error in kick_user: {str(e)}')
        emit('error', {'message': 'Server error while kicking user'})

@socketio.on('user_typing')
def handle_user_typing(data):
    try:
        room_id = data.get('room_id')
        username = data.get('username')
        
        if not room_id or not username:
            return
            
        user = User.query.filter_by(room_id=room_id, username=username).first()
        if not user:
            return
            
        emit('user_typing', {
            'username': username
        }, room=room_id, skip_sid=request.sid)
        
    except Exception as e:
        app.logger.error(f'Error in user_typing: {str(e)}')

@socketio.on('voice_signal')
def handle_voice_signal(data):
    try:
        room_id = data.get('room_id')
        username = data.get('username')
        signal_data = data.get('signal')
        
        if not room_id or not username or not signal_data:
            return
            
        user = User.query.filter_by(room_id=room_id, username=username).first()
        if not user or user.is_muted:
            return
            
        emit('voice_signal', {
            'username': username,
            'signal': signal_data
        }, room=room_id, skip_sid=request.sid)
        
    except Exception as e:
        app.logger.error(f'Error in voice_signal: {str(e)}')

@socketio.on('mute_user')
def handle_mute_user(data):
    try:
        room_id = data.get('room_id')
        username = data.get('username')
        mute_status = data.get('mute', True)
        
        if not room_id or not username:
            emit('error', {'message': 'Missing required data'})
            return
            
        user = User.query.filter_by(room_id=room_id, username=username).first()
        if not user:
            emit('error', {'message': 'User not found'})
            return
            
        user.is_muted = mute_status
        db.session.commit()
        
        emit('user_muted', {
            'username': username,
            'muted': mute_status
        }, room=room_id, broadcast=True)
        
    except Exception as e:
        app.logger.error(f'Error in mute_user: {str(e)}')
        emit('error', {'message': 'Server error while updating mute status'})

@socketio.on('adjust_volume')
def handle_adjust_volume(data):
    try:
        room_id = data.get('room_id')
        username = data.get('username')
        volume_level = data.get('volume', 100)
        
        if not room_id or not username:
            emit('error', {'message': 'Missing required data'})
            return
            
        if not isinstance(volume_level, int) or volume_level < 0 or volume_level > 100:
            emit('error', {'message': 'Invalid volume level'})
            return
            
        user = User.query.filter_by(room_id=room_id, username=username).first()
        if not user:
            emit('error', {'message': 'User not found'})
            return
            
        user.volume_level = volume_level
        db.session.commit()
        
        emit('volume_adjusted', {
            'username': username,
            'volume': volume_level
        }, room=room_id, broadcast=True)
        
    except Exception as e:
        app.logger.error(f'Error in adjust_volume: {str(e)}')
        emit('error', {'message': 'Server error while adjusting volume'})

@socketio.on('disconnect')
def handle_disconnect():
    try:
        user = User.query.filter_by(socket_id=request.sid).first()
        if user:
            room_id = user.room_id
            username = user.username
            
            db.session.delete(user)
            db.session.commit()
            
            user_count = User.query.filter_by(room_id=room_id).count()
            emit('user_left', {
                'username': username,
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'user_count': user_count
            }, room=room_id, broadcast=True)
            
    except Exception as e:
        app.logger.error(f'Error in disconnect: {str(e)}')

@app.errorhandler(404)
def not_found_error(error):
    return jsonify({'error': 'Resource not found', 'message': str(error)}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error', 'message': str(error)}), 500

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)
