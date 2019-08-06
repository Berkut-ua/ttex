import base64
import requests
from datetime import datetime
from datetime import timedelta
# import json

from django.core.cache import cache
from django.conf import settings
from django.core.cache.backends.base import DEFAULT_TIMEOUT


class Tripletex():
    api_domain = 'https://tripletex.no/v2'
    CACHE_TTL = getattr(settings, 'CACHE_TTL', DEFAULT_TIMEOUT)

    def __init__(self, client):
        self.client = client
        self.headers = {'Content-Type': 'application/json; charset=utf-8',
                        'Accept': 'application/json'}

        authorization_redis_key = 'authorization_{}'.format(self.client.id)
        try:
            authorization_in_redis = authorization_redis_key in cache
            redis_ready = True
        except:
            authorization_in_redis = False
            redis_ready = False
        if authorization_in_redis:
            authorization = cache.get(authorization_redis_key)
            print('get fom redis authorization ')
        else:
            auth = self.client.authorization

            consumer_token = auth.get('TTex', {}).get(
                'token_consumer', {}).get('val')
            emploee_token = auth.get('TTex', {}).get(
                'token_employee', {}).get('val')
            if not(consumer_token and emploee_token):
                return False
            session_token = self.create_session_token(consumer_token, emploee_token)

            authorization_str = ':'.join(('0', session_token)).encode('ascii')
            authorization = base64.b64encode(authorization_str).decode('ascii')
            if redis_ready:
                cache.set(authorization_redis_key, authorization, timeout=self.CACHE_TTL)
                print('set to redis authorization ')

        self.headers['Authorization'] = authorization

    def create_session_token(self, consumer_token, emploee_token):
        headers = {'content-type': 'application/json',
                   'accept': 'application/json', }
        domain = 'https://tripletex.no/v2/'
        action = 'token/session/:create?'
        data = {'consumerToken': consumer_token,
                'employeeToken': emploee_token,
                'expirationDate': (datetime.now() + timedelta(days=2)).strftime('%Y-%m-%d'), }
        data_str = '&'.join(['='.join((k, v)) for k, v in data.items()])
        url = ''.join((domain, action, data_str))
        r = requests.put(url, data=data, headers=headers)
        resp = r.json()

        # print(resp)
        try:
            token = resp['value']['token']
        except:
            token = False
        return token

    def get_customers(self, d):
        url = '{}/customer'.format(self.api_domain)
        response = requests.get(url, params=d, headers=self.headers)
        return response.json()

    def get_address(self, address_id):
        url = '{}/address/{}'.format(self.api_domain, address_id)
        response = requests.get(url, headers=self.headers)
        return response.json()

    def get_country(self):
        url = '{}/country'.format(self.api_domain)
        response = requests.get(url,
                                params={'from': 0,'count': 1000},
                                headers=self.headers)
        self.countries = {i.get('id'): i for i in response.json().get('values')}

    def get_invoices(self, date_from, date_to, lim=1000, offset=0):
        # date_from and date_to parameters are in date format
        url = '{}/invoice'.format(self.api_domain)
        response = requests.get(url,
                                params={'invoiceDateFrom': date_from,
                                        'invoiceDateTo': date_to,
                                        'from': offset,
                                        'count': lim},
                                headers=self.headers)
        return response.json()
