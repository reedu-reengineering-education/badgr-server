import base64
from datetime import datetime, timedelta
from hashlib import sha1, sha256
import hmac

import requests
from requests.exceptions import ConnectionError

from django.core.urlresolvers import reverse
from django.conf import settings

blacklist_api_key = getattr(settings, 'BADGR_BLACKLIST_API_KEY', None)
blacklist_query_endpoint = getattr(settings, 'BADGR_BLACKLIST_QUERY_ENDPOINT', None)


def api_submit_email(id_type, email):
    if blacklist_api_key and blacklist_query_endpoint:
        email_hash = _generate_hash(id_type, email)

        try:
            response = requests.post(
                blacklist_query_endpoint, json={"id": email_hash}, headers={
                    "Authorization": "BEARER {api_key}".format(
                        api_key=blacklist_api_key
                    ),
                })
        except ConnectionError:
            return None

        return response
    else:
        return None


def api_query_email(id_type, email):
    if blacklist_api_key and blacklist_query_endpoint:
        email_hash = _generate_hash(id_type, email)

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


def api_query_is_in_blacklist(id_type, email):
    response = api_query_email(id_type, email)

    if response and response.status_code == 200:
        query = response.json()
        if len(query) > 0:
            return True
        else:
            return False

    return None


def _generate_hash(id_type, id_value):
    return "${id_type}$sha256${hash}".format(id_type=id_type,
                                             hash=sha256(id_value).hexdigest())


def generate_email_signature(email):
    secret_key = settings.UNSUBSCRIBE_SECRET_KEY

    expiration = datetime.utcnow() + timedelta(days=7)  # In one week.
    expiration_timestamp = \
        int((expiration - datetime(1970, 1, 1)).total_seconds())

    email_encoded = base64.b64encode(email)
    email_hash = _generate_hash('email', email)
    timestamp_hash = hmac.new(
        secret_key, email_encoded + str(expiration_timestamp), sha1)

    return (email_encoded, email_hash, expiration_timestamp,
            timestamp_hash.hexdigest())


def generate_unsubscribe_path(email):
    email_encoded, _, timestamp, timestamp_hash = \
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
