# encoding: utf-8
from __future__ import unicode_literals

from rest_framework import serializers
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework.exceptions import ValidationError as RestframeworkValidationError

from badgeuser.models import BadgeUser
from issuer.helpers import BadgeCheckHelper
from issuer.models import BadgeInstance
from issuer.serializers_v2 import BadgeRecipientSerializerV2, EvidenceItemSerializerV2
from mainsite.serializers import MarkdownCharField, HumanReadableBooleanField


class BaseSerializerBC(serializers.Serializer):
    @staticmethod
    def response_envelope(result=None):
        envelope = {
            "status": {
                "error": None,
                "statusCode": 200,
                "statusText": 'OK',
            },
        }
        if result is not None:
            envelope['results'] = result

        return envelope


class BCErrorSerializer(serializers.Serializer):
    def __init__(self, *args, **kwargs):
        self.error = kwargs.pop('error', None)
        self.status_text = kwargs.pop('status_text', 'BAD_REQUEST')
        self.status_code = kwargs.pop('status_code', 400)
        super(BCErrorSerializer, self).__init__(*args, **kwargs)
    
    def to_representation(self, instance):
        return {
            "status": {
                "error": self.error,
                "statusCode": self.status_code,
                "statusText": self.status_text
            }
        }

class ListSerializerBC(serializers.ListSerializer, BaseSerializerBC):
    def to_representation(self, instance):
        representation = super(ListSerializerBC, self).to_representation(instance)
        if self.parent is not None:
            return representation
        else:
            return BaseSerializerBC.response_envelope(result=representation)

    @property
    def data(self):
        return super(serializers.ListSerializer, self).data


class BackpackAssertionSerializerBC(BaseSerializerBC):
    id = serializers.URLField(source='jsonld_id', read_only=True)
    badge = serializers.URLField(source='badgeclass_jsonld_id', read_only=True)
    image = serializers.FileField(read_only=True)
    recipient = BadgeRecipientSerializerV2(source='*')
    issuedOn = serializers.DateTimeField(source='issued_on', read_only=True)
    narrative = MarkdownCharField(required=False)
    evidence = EvidenceItemSerializerV2(many=True, required=False)
    revoked = HumanReadableBooleanField(read_only=True)
    revocationReason = serializers.CharField(source='revocation_reason', read_only=True)
    expires = serializers.DateTimeField(source='expires_at', required=False)

    class Meta:
        model = BadgeInstance
        list_serializer_class = ListSerializerBC

    def to_representation(self, instance):
        representation = super(BackpackAssertionSerializerBC, self).to_representation(instance)
        representation['@context'] = 'https://w3id.org/openbadges/v2'
        representation['type'] = 'Assertion'

        return representation


class BackpackImportSerializerBC(BaseSerializerBC):
    id = serializers.URLField()  # This will only work for hosted assertions for now

    def create(self, validated_data):
        url = validated_data['id']
        try:
            instance, created = BadgeCheckHelper.get_or_create_assertion(url=url, created_by=self.context['request'].user)
            if not created:
                instance.acceptance = BadgeInstance.ACCEPTANCE_ACCEPTED
                instance.save()
                raise RestframeworkValidationError([{'name': "DUPLICATE_BADGE", 'description': "You already have this badge in your backpack"}])
        except DjangoValidationError as e:
            raise RestframeworkValidationError(e.messages)
        return instance

    def to_representation(self, instance):
        return self.response_envelope()


class ProfileSerializerBC(BaseSerializerBC):
    name = serializers.SerializerMethodField()
    email = serializers.EmailField()

    class Meta:
        model = BadgeUser

    def get_name(self, instance):
        return '%s %s' % (instance.first_name, instance.last_name)

    def to_representation(self, instance):
        representation = super(ProfileSerializerBC, self).to_representation(instance)
        representation['@context'] = 'https://w3id.org/openbadges/v2'
        return BaseSerializerBC.response_envelope(result=[representation])
