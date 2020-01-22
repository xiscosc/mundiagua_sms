from repositories import AWSUserRepository as UserRepo
from functools import wraps
from flask import jsonify, request

def check_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        user_repo = UserRepo()
        if not user_repo.check_token(token):
            return jsonify({'error': 'Expired or invalid auth token'}), 401

        return f(*args, **kwargs)

    return decorated_function
