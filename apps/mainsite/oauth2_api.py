# encoding: utf-8


import json
import re
import urlparse

from django.http import HttpResponse
from django.utils import timezone
from oauth2_provider.exceptions import OAuthToolkitError
from oauth2_provider.models import get_application_model, get_access_token_model, Application
from oauth2_provider.scopes import get_scopes_backend
from oauth2_provider.settings import oauth2_settings
from oauth2_provider.views import TokenView as OAuth2ProviderTokenView
from oauth2_provider.views.mixins import OAuthLibMixin
from oauthlib.oauth2.rfc6749.utils import scope_to_list
from rest_framework import serializers
from rest_framework.response import Response
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED, HTTP_200_OK, HTTP_201_CREATED
from rest_framework.views import APIView

import badgrlog
from badgeuser.authcode import accesstoken_for_authcode
from backpack.badge_connect_api import BADGE_CONNECT_SCOPES
from mainsite.models import ApplicationInfo
from mainsite.oauth_validator import BadgrRequestValidator, BadgrOauthServer
from mainsite.utils import client_ip_from_request, throttleable

badgrlogger = badgrlog.BadgrLogger()

class AuthorizationSerializer(serializers.Serializer):
    client_id = serializers.CharField(required=True)
    redirect_uri = serializers.URLField(required=True)
    response_type = serializers.CharField(required=False, default=None, allow_null=True)
    state = serializers.CharField(required=False, default=None, allow_null=True)
    scopes = serializers.ListField(child=serializers.CharField())
    scope = serializers.CharField(required=False, default=None, allow_null=True)
    allow = serializers.BooleanField(required=True)


class AuthorizationApiView(OAuthLibMixin, APIView):
    permission_classes = []

    server_class = oauth2_settings.OAUTH2_SERVER_CLASS
    validator_class = oauth2_settings.OAUTH2_VALIDATOR_CLASS
    oauthlib_backend_class = oauth2_settings.OAUTH2_BACKEND_CLASS

    skip_authorization_completely = False

    def get_authorization_redirect_url(self, scopes, credentials, allow=True):
        uri, headers, body, status = self.create_authorization_response(
            request=self.request, scopes=scopes, credentials=credentials, allow=allow)
        return uri

    def post(self, request, *args, **kwargs):
        if not self.request.user.is_authenticated:
            return Response({
                'error': 'Incorrect authentication credentials.'
            }, status=HTTP_401_UNAUTHORIZED)

        # Copy/Pasta'd from oauth2_provider.views.BaseAuthorizationView.form_valid
        try:
            serializer = AuthorizationSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            credentials = {
                "client_id": serializer.data.get("client_id"),
                "redirect_uri": serializer.data.get("redirect_uri"),
                "response_type": serializer.data.get("response_type", None),
                "state": serializer.data.get("state", None),
            }
            if serializer.data.get('scopes'):
                scopes = ' '.join(serializer.data.get("scopes"))
            else:
                scops = serializer.data.get('scope')
            allow = serializer.data.get("allow")

            success_url = self.get_authorization_redirect_url(scopes, credentials, allow)
            return Response({'success_url': success_url})

        except OAuthToolkitError as error:
            return Response({
                'error': error.oauthlib_error.description
            }, status=HTTP_400_BAD_REQUEST)

    def get(self, request, *args, **kwargs):
        application = None
        client_id = request.query_params.get('client_id')
        # Copy/Pasta'd from oauth2_provider.views.BaseAuthorizationView.get
        try:
            scopes, credentials = self.validate_authorization_request(request)
            # all_scopes = get_scopes_backend().get_all_scopes()
            # kwargs["scopes"] = scopes
            # kwargs["scopes_descriptions"] = [all_scopes[scope] for scope in scopes]
            # at this point we know an Application instance with such client_id exists in the database

            # TODO: Cache this!
            application = get_application_model().objects.get(client_id=credentials["client_id"])

            kwargs["client_id"] = credentials["client_id"]
            kwargs["redirect_uri"] = credentials["redirect_uri"]
            kwargs["response_type"] = credentials["response_type"]
            kwargs["state"] = credentials["state"]
            try:
                kwargs["application"] = {
                    "name": application.applicationinfo.get_visible_name(),
                }
                if application.applicationinfo.icon:
                    kwargs["application"]['image'] = application.applicationinfo.icon.url
                if application.applicationinfo.website_url:
                    kwargs["application"]["url"] = application.applicationinfo.website_url
                app_scopes = [s for s in re.split(r'[\s\n]+', application.applicationinfo.allowed_scopes) if s]
            except ApplicationInfo.DoesNotExist:
                app_scopes = ["r:profile"]
                kwargs["application"] = dict(
                    name=application.name,
                    scopes=app_scopes
                )

            filtered_scopes = set(app_scopes) & set(scopes)
            kwargs['scopes'] = list(filtered_scopes)
            all_scopes = get_scopes_backend().get_all_scopes()
            kwargs['scopes_descriptions'] = {scope: all_scopes[scope] for scope in scopes}

            self.oauth2_data = kwargs

            # Check to see if the user has already granted access and return
            # a successful response depending on "approval_prompt" url parameter
            require_approval = request.GET.get("approval_prompt", oauth2_settings.REQUEST_APPROVAL_PROMPT)

            # If skip_authorization field is True, skip the authorization screen even
            # if this is the first use of the application and there was no previous authorization.
            # This is useful for in-house applications-> assume an in-house applications
            # are already approved.
            if application.skip_authorization and not request.user.is_anonymous:
                success_url = self.get_authorization_redirect_url(" ".join(kwargs['scopes']), credentials)
                return Response({'success_url': success_url})

            elif require_approval == "auto" and not request.user.is_anonymous:
                tokens = get_access_token_model().objects.filter(
                    user=request.user,
                    application=application,
                    expires__gt=timezone.now()
                ).all()

                # check past authorizations regarded the same scopes as the current one
                for token in tokens:
                    if token.allow_scopes(scopes):
                        success_url = self.get_authorization_redirect_url(" ".join(kwargs['scopes']), credentials)
                        return Response({'success_url': success_url})

            return Response(kwargs)

        except OAuthToolkitError as error:
            return Response({
                'error': error.oauthlib_error.description
            }, status=HTTP_400_BAD_REQUEST)


class RegistrationSerializer(serializers.Serializer):
    client_name = serializers.CharField(required=True)
    client_uri = serializers.URLField(required=True)
    logo_uri = serializers.URLField(required=True)
    tos_uri = serializers.URLField(required=True)
    policy_uri = serializers.URLField(required=True)
    software_id = serializers.CharField(required=True)
    software_version = serializers.CharField(required=True)
    redirect_uris = serializers.ListField(child=serializers.CharField(), required=True)
    token_endpoint_auth_method = serializers.CharField(required=False)
    grant_types = serializers.ListField(child=serializers.CharField(), required=False)
    response_types = serializers.ListField(child=serializers.CharField(), required=False)
    scope = serializers.CharField(required=False)

class RegistrationResponseSerializer(serializers.Serializer):
    client_id = serializers.CharField(source='application.client_id')
    client_secret = serializers.CharField(source='application.client_secret')
    client_id_issued_at = serializers.SerializerMethodField()
    client_id_expires_at = serializers.IntegerField(default=0)

    def get_client_id_issued_at(self, obj):
        return int(obj.application.created.strftime('%s'))


class RegisterApiView(APIView):
    permission_classes = []
    def post(self, request):
        serializer = RegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        app_model = get_application_model()
        if ApplicationInfo.objects.filter(website_url=serializer.data.get('client_uri')).exists():
            return Response({"error": "Client already registered"}, status=HTTP_400_BAD_REQUEST)
        # All domains in URIs must be HTTPS and match
        uris = set()
        schemes = set()
        def parse_uri(uri):
            parsed = urlparse.urlparse(uri)
            uris.add(parsed.netloc)
            schemes.add(parsed.scheme)
        parse_uri(serializer.data.get('client_uri'))
        parse_uri(serializer.data.get('logo_uri'))
        parse_uri(serializer.data.get('tos_uri'))
        parse_uri(serializer.data.get('policy_uri'))
        for redirect in serializer.data.get('redirect_uris'):
            if app_model.objects.filter(redirect_uris__contains=redirect):
                return Response({"error": "Redirect URI already registered"}, status=HTTP_400_BAD_REQUEST)
            parse_uri(redirect)
        if len(uris) > 1:
            return Response({"error": "URIs do not match"}, status=HTTP_400_BAD_REQUEST)
        if len(schemes) > 1 or schemes.pop() != 'https':
            return Response({"error": "URI schemes must be HTTPS"}, status=HTTP_400_BAD_REQUEST)

        if serializer.data.get('scopes'):
            scopes = serializer.data.get('scopes').split(' ')
            for scope in scopes:
                if scope not in BADGE_CONNECT_SCOPES:
                    return Response({"error": "Invalid scope"}, status=HTTP_400_BAD_REQUEST)
        else:
            # If no scopes provided, we assume they want all scopes
            scopes = BADGE_CONNECT_SCOPES

        if serializer.data.get('token_endpoint_auth_method') != 'client_secret_basic':
            return Response({"error": "Invalid token authentication method"}, status=HTTP_400_BAD_REQUEST)

        if 'authorization_code' not in serializer.data.get('grant_types'):
            return Response({"error": "Missing authorization_code grant type"}, status=HTTP_400_BAD_REQUEST)

        for grant_type in serializer.data.get('grant_types'):
            if grant_type not in ['authorization_code', 'refresh_token']:
                return Response({"error": "Invalid grant types"}, status=HTTP_400_BAD_REQUEST)

        if serializer.data.get('response_types') != ['code']:
            return Response({"error": "Invalid response type"}, status=HTTP_400_BAD_REQUEST)

        app = app_model.objects.create()
        app_info = ApplicationInfo(application=app)

        app.name = serializer.data.get('client_name')
        app.redirect_uris = ' '.join(serializer.data.get('redirect_uris'))
        app.authorization_grant_type = app.GRANT_AUTHORIZATION_CODE
        app.save()

        app_info.website_url = serializer.data.get('client_uri')
        app_info.logo_uri = serializer.data.get('logo_uri')
        app_info.policy_uri = serializer.data.get('policy_uri')
        app_info.software_id = serializer.data.get('software_id')
        app_info.software_version = serializer.data.get('software_version')
        app_info.allowed_scopes = ' '.join(scopes)
        app_info.issue_refresh_token = 'refresh_token' in serializer.data.get('grant_types')
        app_info.save()

        response = RegistrationResponseSerializer(instance=app_info)
        return Response(response.data, status=HTTP_201_CREATED)


class TokenView(OAuth2ProviderTokenView):

    server_class = BadgrOauthServer
    validator_class = BadgrRequestValidator

    @throttleable
    def post(self, request, *args, **kwargs):
        grant_type = request.POST.get('grant_type', 'password')
        username = request.POST.get('username')

        # pre-validate scopes requested
        client_id = request.POST.get('client_id', None)
        requested_scopes = [s for s in scope_to_list(request.POST.get('scope', '')) if s]
        oauth_app = None
        if client_id:
            try:
                oauth_app = Application.objects.get(client_id=client_id)
            except Application.DoesNotExist:
                return HttpResponse(json.dumps({"error": "invalid client_id"}), status=HTTP_400_BAD_REQUEST)

            try:
                allowed_scopes = oauth_app.applicationinfo.scope_list
            except ApplicationInfo.DoesNotExist:
                allowed_scopes = ['r:profile']

            # handle rw:issuer:* scopes
            if 'rw:issuer:*' in allowed_scopes:
                issuer_scopes = [x for x in requested_scopes if x.startswith(r'rw:issuer:')]
                allowed_scopes.extend(issuer_scopes)

            filtered_scopes = set(allowed_scopes) & set(requested_scopes)
            if len(filtered_scopes) < len(requested_scopes):
                return HttpResponse(json.dumps({"error": "invalid scope requested"}), status=HTTP_400_BAD_REQUEST)

        # let parent method do actual authentication
        response = super(TokenView, self).post(request, *args, **kwargs)

        if oauth_app and not oauth_app.applicationinfo.issue_refresh_token:
            data = json.loads(response.content)
            del data['refresh_token']
            response.content = json.dumps(data)

        if grant_type == "password" and response.status_code == 401:
            badgrlogger.event(badgrlog.FailedLoginAttempt(request, username, endpoint='/o/token'))

        return response


class AuthCodeExchange(APIView):
    permission_classes = []

    def post(self, request, **kwargs):
        def _error_response():
            return Response({"error": "Invalid authcode"}, status=HTTP_400_BAD_REQUEST)

        code = request.data.get('code')
        if not code:
            return _error_response()

        accesstoken = accesstoken_for_authcode(code)
        if accesstoken is None:
            return _error_response()

        data = dict(
            access_token=accesstoken.token,
            token_type="Bearer",
            scope=accesstoken.scope
        )

        return Response(data, status=HTTP_200_OK)
