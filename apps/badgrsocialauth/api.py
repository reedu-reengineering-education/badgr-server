from allauth.socialaccount.adapter import get_adapter
from allauth.socialaccount.models import SocialAccount
from django.core.exceptions import ValidationError
from django.http import Http404
from django.urls import reverse
from oauth2_provider.models import AccessToken
from rest_framework.response import Response
from rest_framework.status import HTTP_404_NOT_FOUND, HTTP_204_NO_CONTENT, HTTP_403_FORBIDDEN
from rest_framework.views import APIView

from badgeuser.authcode import authcode_for_accesstoken
from badgeuser.models import UserRecipientIdentifier
from badgrsocialauth.permissions import IsSocialAccountOwner
from badgrsocialauth.serializers_v1 import BadgrSocialAccountSerializerV1
from badgrsocialauth.serializers_v2 import BadgrSocialAccountSerializerV2
from entity.api import BaseEntityListView, BaseEntityDetailView
from entity.serializers import BaseSerializerV2
from issuer.permissions import BadgrOAuthTokenHasScope
from mainsite.utils import OriginSetting


class BadgrSocialAccountList(BaseEntityListView):
    model = SocialAccount
    v1_serializer_class = BadgrSocialAccountSerializerV1
    v2_serializer_class = BadgrSocialAccountSerializerV2
    permission_classes = (BadgrOAuthTokenHasScope,)
    valid_scopes = {
        'get': ['r:profile', 'rw:profile'],
        'post': ['rw:profile']
    }

    def get_objects(self, request, **kwargs):
        obj = self.request.user.socialaccount_set.all()
        return obj

    def get(self, request, **kwargs):
        return super(BadgrSocialAccountList, self).get(request, **kwargs)


class BadgrSocialAccountConnect(APIView):
    permission_classes = (BadgrOAuthTokenHasScope,)
    valid_scopes = ['rw:profile']

    def get(self, request, **kwargs):
        if not isinstance(request.auth, AccessToken):
            raise ValidationError("Invalid credentials")
        provider_name = self.request.GET.get('provider', None)
        if provider_name is None:
            raise ValidationError('No provider specified')

        authcode = authcode_for_accesstoken(request.auth)

        redirect_url = "{origin}{url}?provider={provider}&authCode={code}".format(
            origin=OriginSetting.HTTP,
            url=reverse('socialaccount_login'),
            provider=provider_name,
            code=authcode)

        response_data = dict(url=redirect_url)
        if kwargs['version'] == 'v1':
            return Response(response_data)

        return Response(BaseSerializerV2.response_envelope(response_data, True, 'OK'))


class BadgrSocialAccountDetail(BaseEntityDetailView):
    model = SocialAccount
    v1_serializer_class = BadgrSocialAccountSerializerV1
    v2_serializer_class = BadgrSocialAccountSerializerV2
    permission_classes = (BadgrOAuthTokenHasScope, IsSocialAccountOwner)
    valid_scopes = {
        'get': ['r:profile', 'rw:profile'],
        'post': ['rw:profile'],
        'delete': ['rw:profile']
    }

    def get_object(self, request, **kwargs):
        try:
            return SocialAccount.objects.get(id=kwargs.get('id'))
        except SocialAccount.DoesNotExist:
            raise Http404

    def get(self, request, **kwargs):
        return super(BadgrSocialAccountDetail, self).get(request, **kwargs)

    def delete(self, request, **kwargs):
        social_account = self.get_object(request, **kwargs)

        if not self.has_object_permissions(request, social_account):
            return Response(status=HTTP_404_NOT_FOUND)

        try:
            user_social_accounts = SocialAccount.objects.filter(user=request.user)
            get_adapter().validate_disconnect(social_account, user_social_accounts)
        except ValidationError as e:
            return Response(e.message, status=HTTP_403_FORBIDDEN)

        if social_account.provider == 'twitter':
            identifier = 'https://twitter.com/{}'.format(social_account.extra_data.get('screen_name', '').lower())
            try:
                uri = UserRecipientIdentifier.objects.get(identifier=identifier)
                uri.delete()
            except UserRecipientIdentifier.DoesNotExist:
                pass

        social_account.delete()

        return Response(status=HTTP_204_NO_CONTENT)
