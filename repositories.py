import abc
import os
import boto3
from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError
from utils import get_timestamp, verify_password, generate_token


class SmsRepository(abc.ABC):
    @abc.abstractmethod
    def get_sms_by_id(self, sms_id):
        pass

    @abc.abstractmethod
    def get_sms_by_sender(self, sender):
        pass

    @abc.abstractmethod
    def save_sms(self, sms_object):
        pass


class UserRepository(abc.ABC):
    @abc.abstractmethod
    def get_user_by_username(self, username):
        pass

    @abc.abstractmethod
    def check_token(self, token):
        pass

    @abc.abstractmethod
    def generate_token(self, username, password):
        pass


class AWSSmsRepository(SmsRepository):
    def __init__(self):
        self.client = boto3.resource('dynamodb', region_name='eu-west-1')
        self.table = self.client.Table(os.environ['SMS_TABLE'])

    def get_sms_by_id(self, sms_id):
        try:
            resp = self.table.get_item(Key={'messageId': sms_id})
            if 'Item' in resp:
                return resp['Item']
        except ClientError as e:
            print(e.response['Error']['Message'])

        return None

    def get_sms_by_sender(self, sender):
        try:
            return self.table.scan(FilterExpression=Key('msisdn').eq(sender))
        except ClientError as e:
            print(e.response['Error']['Message'])
            return None

    def save_sms(self, sms_dict):
        try:
            resp = self.table.put_item(Item=sms_dict)
            return True
        except ClientError as e:
            print(e.response['Error']['Message'])
            return None


class AWSUserRepository(UserRepository):
    def __init__(self):
        self.client = boto3.resource('dynamodb', region_name='eu-west-1')
        self.table = self.client.Table(os.environ['USERS_TABLE'])

    def get_user_by_username(self, username):
        try:
            resp = self.table.get_item(Key={'username': username})
            if 'Item' in resp:
                return resp['Item']
        except ClientError as e:
            print(e.response['Error']['Message'])

        return None

    def check_token(self, token):
        if not token:
            return None
        try:
            data = self.table.scan(FilterExpression=Attr('auth_token').eq(token) and Attr('timestamp').gt(get_timestamp(0)))
            if int(data['Count']) == 1:
                return data['Items'][0]['username']
        except ClientError as e:
            print(e.response['Error']['Message'])
        except Exception as e:
            print(e)

        return None

    def generate_token(self, username, password):
        user = self.get_user_by_username(username)
        if user is None:
            return None, None

        if not verify_password(user['password'], password):
            return None, None

        token = generate_token()
        timestamp = get_timestamp(int(os.environ['TOKEN_ALIVE_H']))
        try:
            response = self.table.update_item(
                Key={'username': username},
                UpdateExpression="set auth_token = :t, ts=:times",
                ExpressionAttributeValues={
                    ':t': token,
                    ':times': timestamp,
                },
                ReturnValues="UPDATED_NEW"
            )

            return token, timestamp
        except ClientError as e:
            print(e.response['Error']['Message'])
            return None, None
