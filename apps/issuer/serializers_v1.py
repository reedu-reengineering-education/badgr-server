import os
import pytz
import uuid

from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.urlresolvers import reverse
from django.core.validators import EmailValidator, URLValidator
from django.db.models import Q
from django.utils.html import strip_tags
from django.utils import timezone
from rest_framework import serializers

from . import utils
from badgeuser.serializers_v1 import BadgeUserProfileSerializerV1, BadgeUserIdentifierFieldV1
from mainsite.drf_fields import ValidImageField
from mainsite.models import BadgrApp
from mainsite.serializers import DateTimeWithUtcZAtEndField, HumanReadableBooleanField, StripTagsCharField, MarkdownCharField, \
    OriginalJsonSerializerMixin
from mainsite.utils import OriginSetting
from mainsite.validators import ChoicesValidator, BadgeExtensionValidator, PositiveIntegerValidator, TelephoneValidator
from .models import Issuer, BadgeClass, IssuerStaff, BadgeInstance, RECIPIENT_TYPE_EMAIL, RECIPIENT_TYPE_ID, RECIPIENT_TYPE_URL


class CachedListSerializer(serializers.ListSerializer):
    def to_representation(self, data):
        return [self.child.to_representation(item) for item in data]


class IssuerStaffSerializerV1(serializers.Serializer):
    """ A read_only serializer for staff roles """
    user = BadgeUserProfileSerializerV1(source='cached_user')
    role = serializers.CharField(validators=[ChoicesValidator(list(dict(IssuerStaff.ROLE_CHOICES).keys()))])

    class Meta:
        list_serializer_class = CachedListSerializer

        apispec_definition = ('IssuerStaff', {
            'properties': {
                'role': {
                    'type': "string",
                    'enum': ["staff", "editor", "owner"]

                }
            }
        })


class IssuerSerializerV1(OriginalJsonSerializerMixin, serializers.Serializer):
    created_at = DateTimeWithUtcZAtEndField(read_only=True)
    created_by = BadgeUserIdentifierFieldV1()
    name = StripTagsCharField(max_length=1024)
    slug = StripTagsCharField(max_length=255, source='entity_id', read_only=True)
    image = ValidImageField(required=False)
    email = serializers.EmailField(max_length=255, required=True)
    description = StripTagsCharField(max_length=16384, required=False)
    url = serializers.URLField(max_length=1024, required=True)
    staff = IssuerStaffSerializerV1(read_only=True, source='cached_issuerstaff', many=True)
    badgrapp = serializers.CharField(read_only=True, max_length=255)

    class Meta:
        apispec_definition = ('Issuer', {})

    def validate_image(self, image):
        if image is not None:
            img_name, img_ext = os.path.splitext(image.name)
            image.name = 'issuer_logo_' + str(uuid.uuid4()) + img_ext
        return image

    def create(self, validated_data, **kwargs):
        user = validated_data['created_by']
        potential_email = validated_data['email']

        if not user.is_email_verified(potential_email):
            raise serializers.ValidationError(
                "Issuer email must be one of your verified addresses. Add this email to your profile and try again.")

        new_issuer = Issuer(**validated_data)

        # set badgrapp
        new_issuer.badgrapp = BadgrApp.objects.get_current(self.context.get('request', None))

        new_issuer.save()
        return new_issuer

    def update(self, instance, validated_data):
        force_image_resize = False
        instance.name = validated_data.get('name')

        if 'image' in validated_data:
            instance.image = validated_data.get('image')
            force_image_resize = True

        instance.email = validated_data.get('email')
        instance.description = validated_data.get('description')
        instance.url = validated_data.get('url')

        # set badgrapp
        if not instance.badgrapp_id:
            instance.badgrapp = BadgrApp.objects.get_current(self.context.get('request', None))

        instance.save(force_resize=force_image_resize)
        return instance

    def to_representation(self, obj):
        representation = super(IssuerSerializerV1, self).to_representation(obj)
        representation['json'] = obj.get_json(obi_version='1_1', use_canonical_id=True)

        if self.context.get('embed_badgeclasses', False):
            representation['badgeclasses'] = BadgeClassSerializerV1(obj.badgeclasses.all(), many=True, context=self.context).data

        representation['badgeClassCount'] = len(obj.cached_badgeclasses())
        representation['recipientGroupCount'] = len(obj.cached_recipient_groups())
        representation['recipientCount'] = sum(g.member_count() for g in obj.cached_recipient_groups())
        representation['pathwayCount'] = len(obj.cached_pathways())

        return representation


class IssuerRoleActionSerializerV1(serializers.Serializer):
    """ A serializer used for validating user role change POSTS """
    action = serializers.ChoiceField(('add', 'modify', 'remove'), allow_blank=True)
    username = serializers.CharField(allow_blank=True, required=False)
    email = serializers.EmailField(allow_blank=True, required=False)
    role = serializers.CharField(
        validators=[ChoicesValidator(list(dict(IssuerStaff.ROLE_CHOICES).keys()))],
        default=IssuerStaff.ROLE_STAFF)

    def validate(self, attrs):
        if attrs.get('username') and attrs.get('email'):
            raise serializers.ValidationError(
                'Either a username or email address must be provided, not both.')
        return attrs


class AlignmentItemSerializerV1(serializers.Serializer):
    target_name = StripTagsCharField()
    target_url = serializers.URLField()
    target_description = StripTagsCharField(required=False, allow_blank=True, allow_null=True)
    target_framework = StripTagsCharField(required=False, allow_blank=True, allow_null=True)
    target_code = StripTagsCharField(required=False, allow_blank=True, allow_null=True)

    class Meta:
        apispec_definition = ('BadgeClassAlignment', {})


class BadgeClassExpirationSerializerV1(serializers.Serializer):
    amount = serializers.IntegerField(source='expires_amount', allow_null=True, validators=[PositiveIntegerValidator()])
    duration = serializers.ChoiceField(source='expires_duration', allow_null=True, choices=BadgeClass.EXPIRES_DURATION_CHOICES)


class BadgeClassSerializerV1(OriginalJsonSerializerMixin, serializers.Serializer):
    created_at = DateTimeWithUtcZAtEndField(read_only=True)
    created_by = BadgeUserIdentifierFieldV1()
    id = serializers.IntegerField(required=False, read_only=True)
    name = StripTagsCharField(max_length=255)
    image = ValidImageField(required=False)
    slug = StripTagsCharField(max_length=255, read_only=True, source='entity_id')
    criteria = MarkdownCharField(allow_blank=True, required=False, write_only=True)
    criteria_text = MarkdownCharField(required=False, allow_null=True, allow_blank=True)
    criteria_url = StripTagsCharField(required=False, allow_blank=True, allow_null=True, validators=[URLValidator()])
    recipient_count = serializers.IntegerField(required=False, read_only=True)
    pathway_element_count = serializers.IntegerField(required=False, read_only=True)
    description = StripTagsCharField(max_length=16384, required=True, convert_null=True)

    alignment = AlignmentItemSerializerV1(many=True, source='alignment_items', required=False)
    tags = serializers.ListField(child=StripTagsCharField(max_length=1024), source='tag_items', required=False)

    expires = BadgeClassExpirationSerializerV1(source='*', required=False, allow_null=True)

    class Meta:
        apispec_definition = ('BadgeClass', {})

    def to_internal_value(self, data):
        if 'expires' in data:
            if not data['expires'] or len(data['expires']) == 0:
                # if expires was included blank, remove it so to_internal_value() doesnt choke
                del data['expires']
        return super(BadgeClassSerializerV1, self).to_internal_value(data)

    def to_representation(self, instance):
        representation = super(BadgeClassSerializerV1, self).to_representation(instance)
        representation['issuer'] = OriginSetting.HTTP+reverse('issuer_json', kwargs={'entity_id': instance.cached_issuer.entity_id})
        representation['json'] = instance.get_json(obi_version='1_1', use_canonical_id=True)
        return representation

    def validate_image(self, image):
        if image is not None:
            img_name, img_ext = os.path.splitext(image.name)
            image.name = 'issuer_badgeclass_' + str(uuid.uuid4()) + img_ext
        return image

    def validate_criteria_text(self, criteria_text):
        if criteria_text is not None and criteria_text != '':
            return criteria_text
        else:
            return None

    def validate_criteria_url(self, criteria_url):
        if criteria_url is not None and criteria_url != '':
            return criteria_url
        else:
            return None

    def update(self, instance, validated_data):
        force_image_resize = False

        new_name = validated_data.get('name')
        if new_name:
            new_name = strip_tags(new_name)
            instance.name = new_name

        new_description = validated_data.get('description')
        if new_description:
            instance.description = strip_tags(new_description)

        if 'criteria_text' in validated_data:
            instance.criteria_text = validated_data.get('criteria_text')
        if 'criteria_url' in validated_data:
            instance.criteria_url = validated_data.get('criteria_url')

        if 'image' in validated_data:
            instance.image = validated_data.get('image')
            force_image_resize = True

        instance.alignment_items = validated_data.get('alignment_items')
        instance.tag_items = validated_data.get('tag_items')


        instance.expires_amount = validated_data.get('expires_amount', None)
        instance.expires_duration = validated_data.get('expires_duration', None)

        instance.save(force_resize=force_image_resize)

        return instance

    def validate(self, data):
        if 'criteria' in data:
            if 'criteria_url' in data or 'criteria_text' in data:
                raise serializers.ValidationError(
                    "The criteria field is mutually-exclusive with the criteria_url and criteria_text fields"
                )

            if utils.is_probable_url(data.get('criteria')):
                data['criteria_url'] = data.pop('criteria')
            elif not isinstance(data.get('criteria'), str):
                raise serializers.ValidationError(
                    "Provided criteria text could not be properly processed as URL or plain text."
                )
            else:
                data['criteria_text'] = data.pop('criteria')

        else:
            if data.get('criteria_text', None) is None and data.get('criteria_url', None) is None:
                raise serializers.ValidationError(
                    "One or both of the criteria_text and criteria_url fields must be provided"
                )

        return data

    def create(self, validated_data, **kwargs):

        if 'image' not in validated_data:
            raise serializers.ValidationError({"image": ["This field is required"]})

        if 'issuer' in self.context:
            validated_data['issuer'] = self.context.get('issuer')

        new_badgeclass = BadgeClass.objects.create(**validated_data)
        return new_badgeclass


class EvidenceItemSerializer(serializers.Serializer):
    evidence_url = serializers.URLField(max_length=1024, required=False, allow_blank=True)
    narrative = MarkdownCharField(required=False, allow_blank=True)

    class Meta:
        apispec_definition = ('AssertionEvidence', {})

    def validate(self, attrs):
        if not (attrs.get('evidence_url', None) or attrs.get('narrative', None)):
            raise serializers.ValidationError("Either url or narrative is required")
        return attrs


class BadgeInstanceSerializerV1(OriginalJsonSerializerMixin, serializers.Serializer):
    created_at = DateTimeWithUtcZAtEndField(read_only=True, default_timezone=pytz.utc)
    created_by = BadgeUserIdentifierFieldV1(read_only=True)
    slug = serializers.CharField(max_length=255, read_only=True, source='entity_id')
    image = serializers.FileField(read_only=True)  # use_url=True, might be necessary
    email = serializers.EmailField(max_length=1024, required=False, write_only=True)
    recipient_identifier = serializers.CharField(max_length=1024, required=False)
    recipient_type = serializers.CharField(default=RECIPIENT_TYPE_EMAIL)
    allow_uppercase = serializers.BooleanField(default=False, required=False, write_only=True)
    evidence = serializers.URLField(write_only=True, required=False, allow_blank=True, max_length=1024)
    narrative = MarkdownCharField(required=False, allow_blank=True, allow_null=True)
    evidence_items = EvidenceItemSerializer(many=True, required=False)

    revoked = HumanReadableBooleanField(read_only=True)
    revocation_reason = serializers.CharField(read_only=True)

    expires = DateTimeWithUtcZAtEndField(source='expires_at', required=False, allow_null=True, default_timezone=pytz.utc)

    create_notification = HumanReadableBooleanField(write_only=True, required=False, default=False)
    allow_duplicate_awards = serializers.BooleanField(write_only=True, required=False, default=True)
    hashed = serializers.NullBooleanField(default=None, required=False)

    extensions = serializers.DictField(source='extension_items', required=False, validators=[BadgeExtensionValidator()])

    class Meta:
        apispec_definition = ('Assertion', {})

    def validate(self, data):
        recipient_type = data.get('recipient_type')
        if data.get('recipient_identifier') and data.get('email') is None:
            if recipient_type == RECIPIENT_TYPE_EMAIL:
                recipient_validator = EmailValidator()
            elif recipient_type in (RECIPIENT_TYPE_URL, RECIPIENT_TYPE_ID):
                recipient_validator = URLValidator()
            else:
                recipient_validator = TelephoneValidator()

            try:
                recipient_validator(data['recipient_identifier'])
            except DjangoValidationError as e:
                raise serializers.ValidationError(e.message)

        elif data.get('email') and data.get('recipient_identifier') is None:
            data['recipient_identifier'] = data.get('email')

        allow_duplicate_awards = data.pop('allow_duplicate_awards')
        if allow_duplicate_awards is False and self.context.get('badgeclass') is not None:
            previous_awards = BadgeInstance.objects.filter(
                recipient_identifier=data['recipient_identifier'], badgeclass=self.context['badgeclass']
            ).filter(
                Q(expires_at__isnull=True) | Q(expires_at__lt=timezone.now())
            )
            if previous_awards.exists():
                raise serializers.ValidationError(
                    "A previous award of this badge already exists for this recipient.")

        hashed = data.get('hashed', None)
        if hashed is None:
            if recipient_type in (RECIPIENT_TYPE_URL, RECIPIENT_TYPE_ID):
                data['hashed'] = False
            else:
                data['hashed'] = True

        return data

    def validate_narrative(self, data):
        if data is None or data == "":
            return None
        else:
            return data

    def to_representation(self, instance):
        representation = super(BadgeInstanceSerializerV1, self).to_representation(instance)
        representation['json'] = instance.get_json(obi_version="1_1", use_canonical_id=True)
        if self.context.get('include_issuer', False):
            representation['issuer'] = IssuerSerializerV1(instance.cached_badgeclass.cached_issuer).data
        else:
            representation['issuer'] = OriginSetting.HTTP+reverse('issuer_json', kwargs={'entity_id': instance.cached_issuer.entity_id})
        if self.context.get('include_badge_class', False):
            representation['badge_class'] = BadgeClassSerializerV1(instance.cached_badgeclass, context=self.context).data
        else:
            representation['badge_class'] = OriginSetting.HTTP+reverse('badgeclass_json', kwargs={'entity_id': instance.cached_badgeclass.entity_id})

        representation['public_url'] = OriginSetting.HTTP+reverse('badgeinstance_json', kwargs={'entity_id': instance.entity_id})

        return representation

    def create(self, validated_data):
        """
        Requires self.context to include request (with authenticated request.user)
        and badgeclass: issuer.models.BadgeClass.
        """
        evidence_items = []

        # ob1 evidence url
        evidence_url = validated_data.get('evidence')
        if evidence_url:
            evidence_items.append({'evidence_url': evidence_url})

        # ob2 evidence items
        submitted_items = validated_data.get('evidence_items')
        if submitted_items:
            evidence_items.extend(submitted_items)
        try:
            return self.context.get('badgeclass').issue(
                recipient_id=validated_data.get('recipient_identifier'),
                narrative=validated_data.get('narrative'),
                evidence=evidence_items,
                notify=validated_data.get('create_notification'),
                created_by=self.context.get('request').user,
                allow_uppercase=validated_data.get('allow_uppercase'),
                recipient_type=validated_data.get('recipient_type', RECIPIENT_TYPE_EMAIL),
                badgr_app=BadgrApp.objects.get_current(self.context.get('request')),
                expires_at=validated_data.get('expires_at', None),
                extensions=validated_data.get('extension_items', None)
            )
        except DjangoValidationError as e:
            raise serializers.ValidationError(e.message)

    def update(self, instance, validated_data):
        updateable_fields = [
            'evidence_items',
            'expires_at',
            'extension_items',
            'hashed',
            'narrative',
            'recipient_identifier',
            'recipient_type'
        ]

        for field_name in updateable_fields:
            if field_name in validated_data:
                setattr(instance, field_name, validated_data.get(field_name))
        instance.rebake(save=False)
        instance.save()

        return instance
