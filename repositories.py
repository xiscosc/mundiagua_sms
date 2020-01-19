import abc
import os
import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError


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


class AWSSmsRepository(SmsRepository):
    def __init__(self):
        self.client = boto3.resource('dynamodb', region_name='eu-west-1')
        self.table = self.client.Table(os.environ['SMS_TABLE'])

    def get_sms_by_id(self, sms_id):
        try:
            resp = self.table.get_item(Key={'messageId': sms_id})
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
