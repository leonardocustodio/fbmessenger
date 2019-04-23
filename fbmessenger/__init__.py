from __future__ import absolute_import
import abc
import logging
import os
import uuid

import requests
from dashbot import generic

__version__ = '5.9.45'

logger = logging.getLogger(__name__)
dba = generic.generic(os.environ["DASHBOT_KEY"])
api_url = os.environ["API_URL"]
analytics = os.environ["ANALYTICS"]
fb_access_token = os.environ["FB_ACCESS_TOKEN"]


class Analytics(object):

    @staticmethod
    def save(message, entry, payload, message_type, is_echo=False, thread_control="bot"):

        # Here verifies if users exists if not fills DashUsers
        if not is_echo:
            url_users = '{}/dash-users'.format(api_url)
            headers_users = {'Content-type': 'application/json'}

            request = requests.get('{0}/count?where[psid]={1}'.format(url_users, message.get('sender').get('id')), headers=headers_users)
            if request.ok:
                r_json = request.json()
                # print("PSID: {0} - Count: {1}".format(message.get('sender').get('id'), r_json['count']))

                if r_json['count'] is 0:

                    r = requests.get(
                        'https://graph.facebook.com/v2.11/{sender}'.format(sender=message.get('sender').get('id')),
                        params={
                            'fields': 'name,first_name,last_name,profile_pic,locale,timezone,gender',
                            'access_token': fb_access_token
                        },
                        timeout=None
                    )

                    if r.ok:
                        fb_result = r.json()
                        # print(fb_result)

                        send_user = {
                            "name": fb_result['name'],
                            "firstName": fb_result['first_name'],
                            "lastName": fb_result['last_name'],
                            "profilePic": fb_result['profile_pic'],
                            "locale": fb_result['locale'],
                            "timezone": fb_result['timezone'],
                            "gender": fb_result['gender'],
                            "psid": message.get('sender').get('id')
                        }

                        rx = requests.post(url_users, json=send_user, headers=headers_users)

                        if not rx.ok:
                            print("[Error] Analytics on sending user to database: {0}".format(send_user))
                    else:
                        print("[Error] Analytics on getting user info from facebook: {0}".format(message.get('sender').get('id')))
            else:
                print("[Error] Analytics on getting user count: {0}".format(message.get('sender').get('id')))

        #
        # Here sends the message to dash-messages
        if analytics.lower() == 'false':
            return

        url = '{}/dash-messages'.format(api_url)
        headers = {'Content-type': 'application/json'}

        if message_type is 'message':
            json = {
                'id': str(uuid.uuid4()),
                'senderId': message.get('sender').get('id'),
                'senderType': 'user',
                'recipientId': message.get('recipient').get('id'),
                'msgId': message.get('message').get('mid'),
                'msgContent': message.get('message').get('text'),
                'msgType': 'text',
                'payload': str(payload),
                'channel': 'facebook',
                'source': 'page',
                'flag': False,
                'threadControl': thread_control,
                'timestamp': str(entry.get('time'))
            }

            if message.get('message').get('tags'):
                if message.get('message').get('tags').get('source'):
                    json['source'] = message.get('message').get('tags').get('source')

        elif message_type is 'postback':
            json = {
                'id': str(uuid.uuid4()),
                'senderId': message.get('sender').get('id'),
                'senderType': 'user',
                'recipientId': message.get('recipient').get('id'),
                'msgId': str(entry.get('id')),
                'msgContent': message.get('postback').get('payload'),
                'msgType': 'postback',
                'payload': str(payload),
                'channel': 'facebook',
                'source': 'page',
                'flag': False,
                'threadControl': thread_control,
                'timestamp': str(entry.get('time'))
            }

            if message.get('postback').get('referral'):
                if message.get('postback').get('referral').get('source'):
                    json['source'] = message.get('postback').get('referral').get('source')

        if is_echo is True:
            json['flag'] = True
            if thread_control is "agent":
                json['senderType'] = 'agent'
            else:
                json['senderType'] = 'bot'

        request = requests.post(url, json=json, headers=headers)
        if not request.ok:
            print("[Error] Analytics Save: {0}".format(json))

    @staticmethod
    def send_outgoing(body):
        if analytics.lower() == 'false':
            return

        # Save message to Dashbot
        data = {
            'url': 'https://graph.facebook.com/v2.6/me/messages',
            'qs': {'access_token': fb_access_token},
            'method': 'POST',
            'json': body
        }
        dba.logOutgoing(data)


class MessengerClient(object):

    # https://developers.facebook.com/docs/messenger-platform/send-messages#send_api_basics
    MESSAGING_TYPES = {
        'RESPONSE',
        'UPDATE',
        'MESSAGE_TAG',
    }

    # https://developers.facebook.com/docs/messenger-platform/reference/send-api/
    NOTIFICATION_TYPES = {
        'REGULAR',
        'SILENT_PUSH',
        'NO_PUSH'
    }

    def __init__(self, page_access_token, session=None):
        self.page_access_token = page_access_token
        if session is None:
            session = requests.Session()
        self.session = session

    def get_user_data(self, entry, timeout=None):
        r = self.session.get(
            'https://graph.facebook.com/v2.11/{sender}'.format(sender=entry['sender']['id']),
            params={
                'fields': 'first_name,last_name,profile_pic,locale,timezone,gender',
                'access_token': self.page_access_token
            },
            timeout=timeout
        )
        return r.json()

    def send(self, payload, entry, messaging_type, notification_type=None,
             timeout=None, tag=None):
        if messaging_type not in self.MESSAGING_TYPES:
            raise ValueError(
                '`{}` is not a valid `messaging_type`'.format(messaging_type))

        body = {
            'messaging_type': messaging_type,
            'recipient': {
                'id': entry['sender']['id']
            },
            'message': payload
        }

        if tag:
            body['tag'] = tag

        if notification_type:
            if notification_type not in self.NOTIFICATION_TYPES:
                raise ValueError(
                    '`{}` is not a valid `notification_type`'.format(
                        notification_type))
            body['notification_type'] = notification_type

        Analytics.send_outgoing(body)

        r = self.session.post(
            'https://graph.facebook.com/v2.11/me/messages',
            params={
                'access_token': self.page_access_token
            },
            json=body,
            timeout=timeout
        )

        return r.json()

    def send_action(self, sender_action, entry, timeout=None):
        r = self.session.post(
            'https://graph.facebook.com/v2.11/me/messages',
            params={
                'access_token': self.page_access_token
            },
            json={
                'recipient': {
                    'id': entry['sender']['id']
                },
                'sender_action': sender_action
            },
            timeout=timeout
        )
        return r.json()

    def pass_thread_control(self, target_app_id, metadata, entry, timeout=2):
        r = self.session.post(
            'https://graph.facebook.com/v2.11/me/pass_thread_control',
            params={
                'access_token': self.page_access_token
            },
            json={
                'recipient': {
                    'id': entry['recipient']['id']
                },
                'target_app_id': target_app_id,
                'metadata': metadata
            },
            timeout=timeout
        )
        return r.json()

    def take_thread_control(self, metadata, entry, timeout=2):
        r = self.session.post(
            'https://graph.facebook.com/v2.11/me/take_thread_control',
            params={
                'access_token': self.page_access_token
            },
            json={
                'recipient': {

                    'id': entry['recipient']['id']
                },
                'metadata': metadata
            },
            timeout=timeout
        )
        return r.json()

    def subscribe_app_to_page(self, timeout=None):
        r = self.session.post(
            'https://graph.facebook.com/v2.11/me/subscribed_apps',
            params={
                'access_token': self.page_access_token
            },
            timeout=None
        )
        return r.json()

    def set_messenger_profile(self, data, timeout=None):
        r = self.session.post(
            'https://graph.facebook.com/v2.11/me/messenger_profile',
            params={
                'access_token': self.page_access_token
            },
            json=data,
            timeout=timeout
        )
        return r.json()

    def delete_get_started(self, timeout=None):
        r = self.session.delete(
            'https://graph.facebook.com/v2.11/me/messenger_profile',
            params={
                'access_token': self.page_access_token
            },
            json={
                'fields':[
                    'get_started'
                ],
            },
            timeout=timeout
        )
        return r.json()

    def delete_persistent_menu(self, timeout=None):
        r = self.session.delete(
            'https://graph.facebook.com/v2.11/me/messenger_profile',
            params={
                'access_token': self.page_access_token
            },
            json={
                'fields':[
                    'persistent_menu'
                ],
            },
            timeout=timeout
        )
        return r.json()

    def link_account(self, account_linking_token, timeout=None):
        r = self.session.post(
            'https://graph.facebook.com/v2.11/me',
            params={
                'access_token': self.page_access_token,
                'fields': 'recipient',
                'account_linking_token': account_linking_token
            },
            timeout=timeout
        )
        return r.json()

    def unlink_account(self, psid, timeout=None):
        r = self.session.post(
            'https://graph.facebook.com/v2.11/me/unlink_accounts',
            params={
                'access_token': self.page_access_token
            },
            json={
                'psid': psid
            },
            timeout=timeout
        )
        return r.json()

    def update_whitelisted_domains(self, domains, timeout=None):
        if not isinstance(domains, list):
            domains = [domains]
        r = self.session.post(
            'https://graph.facebook.com/v2.11/me/messenger_profile',
            params={
                'access_token': self.page_access_token
            },
            json={
                'whitelisted_domains': domains
            },
            timeout=timeout
        )
        return r.json()

    def remove_whitelisted_domains(self, timeout=None):
        r = self.session.delete(
            'https://graph.facebook.com/v2.11/me/messenger_profile',
            params={
                'access_token': self.page_access_token
            },
            json={
                'fields':[
                    'whitelisted_domains'
                ],
            },
            timeout=timeout
        )
        return r.json()

    def upload_attachment(self, attachment, timeout=None):
        if not attachment.url:
            raise ValueError('Attachment must have `url` specified')
        if attachment.quick_replies:
            raise ValueError('Attachment may not have `quick_replies`')
        r = self.session.post(
            'https://graph.facebook.com/v2.11/me/message_attachments',
            params={
                'access_token': self.page_access_token
            },
            json={
                'message':  attachment.to_dict()
            },
            timeout=timeout
        )
        return r.json()


class BaseMessenger(object):
    __metaclass__ = abc.ABCMeta

    last_message = {}

    def __init__(self, page_access_token):
        self.page_access_token = page_access_token
        self.client = MessengerClient(self.page_access_token)

    @abc.abstractmethod
    def account_linking(self, message):
        """Method to handle `account_linking`"""

    @abc.abstractmethod
    def message(self, message):
        """Method to handle `messages`"""

    @abc.abstractmethod
    def delivery(self, message):
        """Method to handle `message_deliveries`"""

    @abc.abstractmethod
    def optin(self, message):
        """Method to handle `messaging_optins`"""

    @abc.abstractmethod
    def postback(self, message):
        """Method to handle `messaging_postbacks`"""

    @abc.abstractmethod
    def read(self, message):
        """Method to handle `message_reads`"""

    @abc.abstractmethod
    def echo(self, message):
        """Method to handle `message_echoes`"""

    @abc.abstractmethod
    def handover(self, message):
        """Method to handle `message_handovers`"""

    @abc.abstractmethod
    def referral(self, message):
        """Method to handle referrals"""

    def handle(self, payload):
        print("Handle: {}".format(payload))

        for entry in payload['entry']:
            if 'messaging' in entry:
                for message in entry['messaging']:
                    self.last_message = message
                    if message.get('account_linking'):
                        return self.account_linking(message)
                    elif message.get('delivery'):
                        return self.delivery(message)
                    elif message.get('message'):
                        if message.get('message').get('is_echo') is True:
                            Analytics.save(message, entry, payload, 'message', True, "bot")
                        else:
                            Analytics.save(message, entry, payload, 'message', False, "bot")
                            return self.message(message)
                    elif message.get('optin'):
                        return self.optin(message)
                    elif message.get('postback'):
                        if message.get('postback').get('is_echo') is True:
                            Analytics.save(message, entry, payload, 'postback', True, "bot")
                        else:
                            Analytics.save(message, entry, payload, 'postback', False, "bot")
                            return self.postback(message)
                    elif message.get('read'):
                        return self.read(message)
                    elif message.get('request_thread_control'):
                        return self.handover(message)
                    elif message.get('pass_thread_control'):
                        return self.handover(message)
                    elif message.get('referral'):
                        return self.referral(message)
            elif 'standby' in entry:
                for standby in entry['standby']:
                    self.last_message = standby
                    if standby.get('postback'):
                        Analytics.save(standby, entry, payload, 'postback', False, "agent")
                        standby['postback']['payload'] = standby['postback']['title']
                        return self.postback(standby)
                    elif standby.get('message'):
                        if standby.get('message').get('is_echo') is True:
                            Analytics.save(standby, entry, payload, 'message', True, "agent")
                        else:
                            Analytics.save(standby, entry, payload, 'message', False, "agent")

    def get_user(self, timeout=None):
        return self.client.get_user_data(self.last_message, timeout=timeout)

    def send(self, payload, messaging_type, timeout=None, tag=None):
        return self.client.send(
            payload, self.last_message, messaging_type, timeout=timeout, tag=None)

    def send_action(self, sender_action, timeout=None):
        return self.client.send_action(
            sender_action, self.last_message, timeout=timeout)

    def get_user_id(self):
        return self.last_message['sender']['id']

    def subscribe_app_to_page(self, timeout=None):
        return self.client.subscribe_app_to_page(timeout=timeout)

    def set_messenger_profile(self, data, timeout=None):
        return self.client.set_messenger_profile(data, timeout=timeout)

    def delete_get_started(self, timeout=None):
        return self.client.delete_get_started(timeout=timeout)

    def link_account(self, account_linking_token, timeout=None):
        return self.client.link_account(account_linking_token, timeout=timeout)

    def unlink_account(self, psid, timeout=None):
        return self.client.unlink_account(psid, timeout=timeout)

    def add_whitelisted_domains(self, domains, timeout=None):
        return self.client.update_whitelisted_domains(domains, timeout=timeout)

    def remove_whitelisted_domains(self, timeout=None):
        return self.client.remove_whitelisted_domains(timeout=timeout)

    def upload_attachment(self, attachment, timeout=None):
        return self.client.upload_attachment(attachment, timeout=timeout)
