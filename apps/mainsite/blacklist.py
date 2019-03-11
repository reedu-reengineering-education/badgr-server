import base64
from datetime import datetime, timedelta
from hashlib import sha1
import hmac

import requests
from requests.exceptions import ConnectionError

from django.core.urlresolvers import reverse
from django.conf import settings

blacklist_api_key = getattr(settings, 'BADGR_BLACKLIST_API_KEY', None)
blacklist_query_endpoint = getattr(settings, 'BADGR_BLACKLIST_QUERY_ENDPOINT', None)


def api_submit_email(email):
    if blacklist_api_key and blacklist_query_endpoint:
        email_encoded, email_hash, expiration_timestamp, timestamp_hash = \
            generate_email_signature(email)

        request_body = '{ "id": "%s" }' % email_hash
        request_query = "{endpoint}".format(endpoint=blacklist_query_endpoint)

        try:
            response = requests.post(request_query, request_body, headers={
                "Authorization": "BEARER {api_key}".format(
                    api_key=blacklist_api_key
                ),
            })
        except ConnectionError:
            return None

        return response
    else:
        return None


def api_query_email(email):
    if blacklist_api_key and blacklist_query_endpoint:
        email_encoded, email_hash, expiration_timestamp, timestamp_hash = \
            generate_email_signature(email)

        request_query = "{endpoint}?id={email_hash}".format(
            endpoint=blacklist_query_endpoint,
            email_hash=email_hash)

        try:
            response = requests.get(request_query, headers={
                "Authorization": "BEARER {api_key}".format(
                    api_key=blacklist_api_key
                ),
            })
        except ConnectionError:
            return None

        return response
    else:
        return None


def api_query_is_in_blacklist(email):
    response = api_query_email(email)

    is_in_blacklist = None
    if response and response.status_code == 200:
        query = response.json()
        if len(query) > 0:
            is_in_blacklist = True
        else:
            is_in_blacklist = False

    return is_in_blacklist


def generate_email_signature(email):
    secret_key = settings.UNSUBSCRIBE_SECRET_KEY

    expiration = datetime.utcnow() + timedelta(days=7)  # In one week.
    expiration_timestamp = \
        int((expiration - datetime(1970, 1, 1)).total_seconds())

    email_encoded = base64.b64encode(email)
    email_hash = "email$sha1${hash}".format(
        hash=hmac.new(secret_key, email_encoded, sha1).hexdigest())
    timestamp_hash = hmac.new(
        secret_key, email_encoded + str(expiration_timestamp), sha1)

    return (email_encoded, email_hash, expiration_timestamp,
            timestamp_hash.hexdigest())


def generate_unsubscribe_path(email):
    email_encoded, email_hash, timestamp, timestamp_hash = \
        generate_email_signature(email)

    return reverse('unsubscribe', kwargs={
        'email_encoded': email_encoded,
        'expiration': timestamp,
        'signature': timestamp_hash,
    })


def verify_email_signature(email_encoded, expiration, signature):
    secret_key = settings.UNSUBSCRIBE_SECRET_KEY

    hashed = hmac.new(secret_key, email_encoded + expiration, sha1)
    return hmac.compare_digest(hashed.hexdigest(), str(signature))
