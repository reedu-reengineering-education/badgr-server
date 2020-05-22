from allauth.socialaccount.providers.oauth2.views import OAuth2CallbackView

from .provider import IdTokenOAuth2Client


class IdTokenAuth2CallbackView(OAuth2CallbackView):
    def get_client(self, request, app):
        callback_url = self.adapter.get_callback_url(request, app)
        provider = self.adapter.get_provider()
        scope = provider.get_scope(request)
        client = IdTokenOAuth2Client(
            request, app.client_id, app.secret,
            self.adapter.access_token_method,
            self.adapter.access_token_url,
            callback_url,
            scope,
            scope_delimiter=self.adapter.scope_delimiter,
            headers=self.adapter.headers,
            basic_auth=self.adapter.basic_auth
        )
        return client
