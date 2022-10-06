# settings_local.py is for all instance specific settings

import random
import string
import environ
import os

from apps.mainsite.settings import INSTALLED_APPS
from .settings import *
from mainsite import TOP_DIR

env = environ.Env()

DEBUG = False
DEBUG_ERRORS = DEBUG
DEBUG_STATIC = DEBUG
DEBUG_MEDIA = DEBUG

TIME_ZONE = env('TIME_ZONE')
LANGUAGE_CODE = env('LANGUAGE_CODE')


##
#
# Database Configuration
#
##
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': env('DB_NAME'),
        'USER': env('DB_USER'),
        'PASSWORD': env('DB_PASSWORD'),
        'HOST': env('DB_HOST'),
        'PORT': env('DB_PORT'),
        'OPTIONS': {
#            "SET character_set_connection=utf8mb3, collation_connection=utf8_unicode_ci",  # Uncomment when using MySQL to ensure consistency across servers
        },
    }
}


###
#
# CACHE
#
###
CACHES = {
     'default': {
         'BACKEND': 'django.core.cache.backends.memcached.MemcachedCache',
         'LOCATION': env('CACHE_LOCATION'),
         'KEY_FUNCTION': 'mainsite.utils.filter_cache_key'
     }
 }


###
#
# Email Configuration
#
###
INSTALLED_APPS.append('anymail')
ANYMAIL = {
    "AMAZON_SES_CLIENT_PARAMS": {
        # example: override normal Boto credentials specifically for Anymail
        "aws_access_key_id": env('AWS_ACCESS_KEY_ID'),
        "aws_secret_access_key": env('AWS_ACCESS_KEY_SECRET'),
        "region_name": env('AWS_REGION'),
    },
}
#EMAIL_BACKEND = 'anymail.backends.amazon_ses.EmailBackend'
EMAIL_BACKEND = 'django_ses.SESBackend'
AWS_SES_REGION_NAME = env('AWS_REGION')
AWS_SES_REGION_ENDPOINT = 'email.eu-central-1.amazonaws.com'
DEFAULT_FROM_EMAIL = env('DEFAULT_FROM_EMAIL')  # if you don't already have this in settings
SERVER_EMAIL = env('SERVER_EMAIL')  # ditto (default from-email for Django errors)


###
#
# Storage Configuration
#
###
DEFAULT_FILE_STORAGE = 'storages.backends.s3boto3.S3Boto3Storage'
AWS_QUERYSTRING_AUTH=False
AWS_ACCESS_KEY_ID=env('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY=env('AWS_ACCESS_KEY_SECRET')
AWS_STORAGE_BUCKET_NAME=env('AWS_STORAGE_BUCKET_NAME')


###
#
# Celery Asynchronous Task Processing (Optional)
#
###
CELERY_RESULT_BACKEND = None
# Run celery tasks in same thread as webserver (True means that asynchronous processing is OFF)
CELERY_ALWAYS_EAGER = True


###
#
# Application Options Configuration
#
###
HTTP_ORIGIN = env('HTTP_ORIGIN')
ALLOWED_HOSTS = ['*']
STATIC_URL = HTTP_ORIGIN + '/static/'

# Optionally restrict issuer creation to accounts that have the 'issuer.add_issuer' permission
BADGR_APPROVED_ISSUERS_ONLY = False

# Automatically send an email the first time that recipient identifier (email type) has been used on the system.
GDPR_COMPLIANCE_NOTIFY_ON_FIRST_AWARD = True

SECRET_KEY = env('SECRET_KEY').join(random.choice(string.ascii_uppercase + string.digits) for _ in range(40))
UNSUBSCRIBE_KEY = env('UNSUBSCRIBE_KEY').join(random.choice(string.ascii_uppercase + string.digits) for _ in range(40))
UNSUBSCRIBE_SECRET_KEY = str(SECRET_KEY)


###
#
# Logging
#
###
LOGS_DIR = os.path.join(TOP_DIR, 'logs')
if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR)
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'mail_admins': {
            'level': 'ERROR',
            'filters': [],
            'class': 'django.utils.log.AdminEmailHandler'
        },

        # badgr events log to disk by default
        'badgr_events': {
            'level': 'INFO',
            'formatter': 'json',
            'class': 'logging.FileHandler',
            'filename': os.path.join(LOGS_DIR, 'badgr_events.log')
        }
    },
    'loggers': {
        'django.request': {
            'handlers': ['mail_admins'],
            'level': 'ERROR',
            'propagate': True,
        },

        # Badgr.Events emits all badge related activity
        'Badgr.Events': {
            'handlers': ['badgr_events'],
            'level': 'INFO',
            'propagate': False,

        }

    },
    'formatters': {
        'default': {
            'format': '%(asctime)s %(levelname)s %(module)s %(message)s'
        },
        'json': {
            '()': 'mainsite.formatters.JsonFormatter',
            'format': '%(asctime)s',
            'datefmt': '%Y-%m-%dT%H:%M:%S%z',
        }
    },
}

