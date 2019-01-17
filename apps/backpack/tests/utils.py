import os
import responses

CURRENT_DIRECTORY = os.path.dirname(__file__)


def setup_basic_1_0(**kwargs):
    if not kwargs or not 'http://a.com/instance' in kwargs.get('exclude', []):
        responses.add(
            responses.GET, 'http://a.com/instance',
            body=open(os.path.join(CURRENT_DIRECTORY, 'testfiles/1_0_basic_instance.json')).read(),
            status=200, content_type='application/json'
        )
    if not kwargs or not 'http://a.com/badgeclass' in kwargs.get('exclude', []):
        responses.add(
            responses.GET, 'http://a.com/badgeclass',
            body=open(os.path.join(CURRENT_DIRECTORY, 'testfiles/1_0_basic_badgeclass.json')).read(),
            status=200, content_type='application/json'
        )
    if not kwargs or not 'http://a.com/issuer' in kwargs.get('exclude', []):
        responses.add(
            responses.GET, 'http://a.com/issuer',
            body=open(os.path.join(CURRENT_DIRECTORY, 'testfiles/1_0_basic_issuer.json')).read(),
            status=200, content_type='application/json'
        )
    if not kwargs or not 'http://a.com/badgeclass_image' in kwargs.get('exclude', []):
        responses.add(
            responses.GET, 'http://a.com/badgeclass_image',
            body=open(os.path.join(CURRENT_DIRECTORY, 'testfiles/unbaked_image.png')).read(),
            status=200, content_type='image/png'
        )


def setup_resources(resources):
    for item in resources:
        response_body = item.get('response_body')
        if response_body is None:
            response_body = open(os.path.join(CURRENT_DIRECTORY, 'testfiles', item['filename'])).read()
        responses.add(
            responses.GET, item['url'],
            body=response_body,
            status=item.get('status', 200),
            content_type=item.get('content_type', 'application/json')

        )


def setup_basic_0_5_0(**kwargs):
    responses.add(
        responses.GET, 'http://oldstyle.com/instance',
        body=open(os.path.join(CURRENT_DIRECTORY, 'testfiles/0_5_basic_instance.json')).read(),
        status=200, content_type='application/json'
    )
    if not kwargs or not 'http://oldstyle.com/images/1' in kwargs.get('exclude'):
        responses.add(
            responses.GET, 'http://oldstyle.com/images/1',
            body=open(os.path.join(CURRENT_DIRECTORY, 'testfiles/unbaked_image.png')).read(),
            status=200, content_type='image/png'
        )
