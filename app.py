from flask import Flask, jsonify, request
from repositories import AWSSmsRepository as SMSRepo, AWSUserRepository as UserRepo, AWSPhonesRepository as PhoneRepo
from decorators import check_token
from utils import SMSJSONEncoder
app = Flask(__name__)
app.json_encoder = SMSJSONEncoder


@app.route("/")
@check_token
def hello():
    return "Mundiagua SMS Service"


@app.route("/phones")
@check_token
def get_phones():
    repository = PhoneRepo()
    scan_data = repository.get_phones()
    if not scan_data:
        return jsonify({'error': 'Error getting Phones'}), 500

    response = {
        'count': scan_data['Count'],
        'items': scan_data['Items'],
    }

    return jsonify(response)


@app.route("/sms/sender/<string:msisdn>")
@check_token
def get_sms_by_sender(msisdn):
    repository = SMSRepo()
    scan_data = repository.get_sms_by_sender(msisdn)
    if not scan_data:
        return jsonify({'error': 'Error filtering by sender'}), 500

    response = {
        'count': scan_data['Count'],
        'items': scan_data['Items'],
    }

    return jsonify(response)


@app.route("/sms/<string:sms_id>")
@check_token
def get_sms(sms_id):
    repository = SMSRepo()
    item, phone = repository.get_sms_by_id(sms_id)
    if not item:
        return jsonify({'error': 'SMS does not exist'}), 404

    response = {'sms': item, 'phone': phone}
    return jsonify(response)


@app.route("/sms", methods=["POST"])
def create_sms():
    repository = SMSRepo()
    message_id = request.json.get('messageId')
    msisdn = request.json.get('msisdn')
    if not message_id or not msisdn:
        return jsonify({'error': 'Invalid json format'}), 400

    json = request.get_json()
    result = repository.save_sms(json)
    if not result:
        return jsonify({'error': 'Error saving SMS'}), 500

    return jsonify({
        'messageId': message_id,
        'msisdn': msisdn
    })


@app.route("/user_token", methods=["POST"])
def get_user_token():
    repository = UserRepo()
    if not request.json:
        return jsonify({'error': 'Invalid json format'}), 400

    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        return jsonify({'error': 'Invalid json format'}), 400

    token, timestamp = repository.generate_token(username, password)
    if not token:
        return jsonify({'error': 'Unauthorised'}), 401

    return jsonify({
        'token': token,
        'timestamp': timestamp,
    })
