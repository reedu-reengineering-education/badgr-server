"""
Utility functions and constants that might be used across the project.
"""
from __future__ import unicode_literals

import StringIO
import base64
import hashlib
import re
import urllib
import urlparse
import uuid
import puremagic
import requests
from django.apps import apps
from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import SuspiciousFileOperation
from django.core.files.storage import DefaultStorage
from django.core.urlresolvers import get_callable
from xml.etree import cElementTree as ET


class ObjectView(object):
    """
    A simple utility that allows Rest Framework Serializers to serialize dict-based input
    when there is no appropriate model Class to instantiate.

    Instantiate an ObjectView(source_dict) in the serializer's to_internal_value() method.
    """
    def __init__(self, d):
        self.__dict__ = d

    def __unicode__(self):
        return str(self.__dict__)


slugify_function_path = \
    getattr(settings, 'AUTOSLUG_SLUGIFY_FUNCTION', 'autoslug.utils.slugify')

slugify = get_callable(slugify_function_path)

def installed_apps_list():
    installed_apps = []
    for app in ('issuer', 'composition', 'badgebook'):
        if apps.is_installed(app):
            installed_apps.append(app)
    return installed_apps


def client_ip_from_request(request):
    """Returns the IP of the request, accounting for the possibility of being behind a proxy.
    """
    ip = request.META.get("HTTP_X_FORWARDED_FOR", None)
    if ip:
        # X_FORWARDED_FOR returns client1, proxy1, proxy2,...
        ip = ip.split(", ")[0]
    else:
        ip = request.META.get("REMOTE_ADDR", "")
    return ip


def backoff_cache_key(username=None, client_ip=None):
    client_descriptor = username if username else client_ip
    return "failed_token_backoff_{}".format(client_descriptor)


class OriginSettingsObject(object):
    DefaultOrigin = "http://localhost:8000"

    @property
    def DEFAULT_HTTP_PROTOCOL(self):
        parsed = urlparse.urlparse(self.HTTP)
        return parsed.scheme

    @property
    def HTTP(self):
        return getattr(settings, 'HTTP_ORIGIN', OriginSettingsObject.DefaultOrigin)

OriginSetting = OriginSettingsObject()

"""
Cache Utilities
"""
def filter_cache_key(key, key_prefix, version):
    generated_key = ':'.join([key_prefix, str(version), key])
    if len(generated_key) > 250:
        return hashlib.md5(generated_key).hexdigest()
    return generated_key


def verify_svg(fileobj):
    """
    Check if provided file is svg
    from: https://gist.github.com/ambivalentno/9bc42b9a417677d96a21
    """
    fileobj.seek(0)
    tag = None
    try:
        for event, el in ET.iterparse(fileobj, events=(b'start',)):
            tag = el.tag
            break
    except ET.ParseError:
        pass
    return tag == '{http://www.w3.org/2000/svg}svg'


def scrubSvgElementTree(svg_elem):
    """
    Takes an element (https://docs.python.org/2/library/xml.etree.elementtree.html#element-objects)
    from an element tree then scrubs malicious tags and attributes.
    :return: (svg_elem)
    """
    MALICIOUS_SVG_TAGS = [
        "script"
    ]
    MALICIOUS_SVG_ATTRIBUTES = [
        "onload"
    ]
    SVG_NAMESPACE = "http://www.w3.org/2000/svg"

    ET.register_namespace("", SVG_NAMESPACE)

    # find malicious tags and attributes
    elements_to_strip = []
    for tag_name in MALICIOUS_SVG_TAGS:
        elements_to_strip.extend(svg_elem.findall('.//{{{ns}}}{tag}'.format(ns=SVG_NAMESPACE, tag=tag_name)))

    # strip malicious tags
    for e in elements_to_strip:
        parent = svg_elem.find(".//{tag}/..".format(tag=e.tag))
        parent.remove(e)

    # strip malicious attributes
    for el in svg_elem.iter():
        for attrib_name in MALICIOUS_SVG_ATTRIBUTES:
            if attrib_name in el.attrib:
                del el.attrib[attrib_name]

    return svg_elem

def fetch_remote_file_to_storage(remote_url, upload_to='', allowed_mime_types=()):
    """
    Fetches a remote url, and stores it in DefaultStorage
    :return: (status_code, new_storage_name)
    """

    SVG_MIME_TYPE = 'image/svg+xml'

    if not allowed_mime_types:
        raise SuspiciousFileOperation("allowed mime types must be passed in")

    store = DefaultStorage()
    r = requests.get(remote_url, stream=True)

    if r.status_code == 200:

        magic_strings = puremagic.magic_string(r.content)
        derived_mime_type = None
        derived_ext = None
        stripped_svg_string = None

        for magic_string in magic_strings:
            if getattr(magic_string, 'mime_type', None) in allowed_mime_types:
                derived_mime_type = getattr(magic_string, 'mime_type', None)
                derived_ext = getattr(magic_string, 'extension', None)
                break

        if not derived_mime_type and re.search(b'<svg', r.content[:1024]) and r.content.strip()[-6:] == b'</svg>':
            derived_mime_type = SVG_MIME_TYPE
            derived_ext = '.svg'

        if derived_mime_type == SVG_MIME_TYPE:
            stripped_svg_element = ET.fromstring(r.content)
            scrubSvgElementTree(stripped_svg_element)
            stripped_svg_string = ET.tostring(stripped_svg_element)

        if derived_mime_type not in allowed_mime_types:
            raise SuspiciousFileOperation("{} is not an allowed mime type for upload".format(derived_mime_type))

        if not derived_ext:
            raise SuspiciousFileOperation("could not determine a file extension")

        storage_name = '{upload_to}/cached/{filename}{ext}'.format(
            upload_to=upload_to,
            filename=hashlib.md5(remote_url).hexdigest(),
            ext=derived_ext)

        string_to_write_to_file = stripped_svg_string or r.content

        if not store.exists(storage_name):
            buf = StringIO.StringIO(string_to_write_to_file)
            store.save(storage_name, buf)
        return r.status_code, storage_name
    return r.status_code, None


def generate_entity_uri():
    """
    Generate a unique url-safe identifier
    """
    entity_uuid = uuid.uuid4()
    b64_string = base64.urlsafe_b64encode(entity_uuid.bytes)
    b64_trimmed = re.sub(r'=+$', '', b64_string)
    return b64_trimmed


def first_node_match(graph, condition):
    """return the first dict in a list of dicts that matches condition dict"""
    for node in graph:
        if all(item in node.items() for item in condition.items()):
            return node


def get_tool_consumer_instance_guid():
    guid = getattr(settings, 'EXTERNALTOOL_CONSUMER_INSTANCE_GUID', None)
    if guid is None:
        guid = cache.get("external_tool_consumer_instance_guid")
        if guid is None:
            guid = "badgr-tool-consumer:{}".format(generate_entity_uri())
            cache.set("external_tool_consumer_instance_guid", guid, timeout=None)
    return guid


def list_of(value):
    if value is None:
        return []
    elif isinstance(value, list):
        return value
    return [value]


def set_url_query_params(url, **kwargs):
    """
    Given a url, possibly including query parameters, return a url with the given query parameters set, replaced on a
    per-key basis.
    """
    url_parts = list(urlparse.urlparse(url))
    query = dict(urlparse.parse_qsl(url_parts[4]))
    query.update(kwargs)
    url_parts[4] = urllib.urlencode(query)
    return urlparse.urlunparse(url_parts)
