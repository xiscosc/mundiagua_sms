from flask import Flask, jsonify, request
from repositories import AWSSmsRepository as SMSRepo

app = Flask(__name__)


@app.route("/")
def hello():
    return "Mundiagua SMS Service"


@app.route("/sms/sender/<string:msisdn>")
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
def get_sms(sms_id):
    repository = SMSRepo()
    item = repository.get_sms_by_id(sms_id)
    if not item:
        return jsonify({'error': 'SMS does not exist'}), 404

    return jsonify(item)


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
