from django.contrib.admin import ModelAdmin, TabularInline
from django.core.cache import cache
from django.utils import timezone
from django_object_actions import DjangoObjectActions

from externaltools.models import ExternalToolUserActivation
from mainsite.admin import badgr_admin
from mainsite.utils import backoff_cache_key
from .models import (BadgeUser, EmailAddressVariant, TermsVersion, TermsAgreement, CachedEmailAddress,
                     UserRecipientIdentifier)


class ExternalToolInline(TabularInline):
    model = ExternalToolUserActivation
    fk_name = 'user'
    fields = ('externaltool',)
    extra = 0


class TermsAgreementInline(TabularInline):
    model = TermsAgreement
    fk_name = 'user'
    extra = 0
    max_num = 0
    can_delete = False
    readonly_fields = ('created_at', 'terms_version')
    fields = ('created_at', 'terms_version')


class EmailAddressInline(TabularInline):
    model = CachedEmailAddress
    fk_name = 'user'
    extra = 0
    fields = ('email','verified','primary')


class UserRecipientIdentifierInline(TabularInline):
    model = UserRecipientIdentifier
    fk_name = 'user'
    extra = 0
    fields = ('type', 'identifier', 'verified')


class BadgeUserAdmin(DjangoObjectActions, ModelAdmin):
    readonly_fields = ('entity_id', 'date_joined', 'last_login', 'username', 'entity_id', 'agreed_terms_version',
                       'login_backoff', 'has_usable_password',)
    list_display = ('email', 'first_name', 'last_name', 'is_active', 'is_staff', 'entity_id', 'date_joined')
    list_filter = ('is_active', 'is_staff', 'is_superuser', 'date_joined', 'last_login')
    search_fields = ('email', 'first_name', 'last_name', 'username', 'entity_id')
    fieldsets = (
        ('Metadata', {'fields': ('entity_id', 'username', 'date_joined',), 'classes': ('collapse',)}),
        (None, {'fields': ('email', 'first_name', 'last_name', 'badgrapp', 'agreed_terms_version', 'marketing_opt_in')}),
        ('Access', {'fields': ('is_active', 'is_staff', 'is_superuser', 'has_usable_password', 'password', 'login_backoff')}),
        ('Permissions', {'fields': ('groups', 'user_permissions')}),
    )
    inlines = [
        EmailAddressInline,
        UserRecipientIdentifierInline,
        ExternalToolInline,
        TermsAgreementInline,
    ]
    change_actions = [
        'clear_login_backoff'
    ]

    def clear_login_backoff(self, request, obj):
        for email in obj.all_verified_recipient_identifiers:
            cache_key = backoff_cache_key(username=email)
            cache.delete(cache_key)
    clear_login_backoff.label = "Clear login backoffs"
    clear_login_backoff.short_description = "Remove blocks created by failed login attempts"

    def login_backoff(self, obj):
        out = []
        for email in obj.all_verified_recipient_identifiers:
            cache_key = backoff_cache_key(username=email)
            backoff = cache.get(cache_key)
            if backoff is not None:
                out.append("<div><strong>{email}</strong>: <span>{until}</span> <span>({count} attempts)</span></div>".format(
                    email=email,
                    until=backoff.get('until').astimezone(timezone.get_current_timezone()).strftime("%Y-%m-%d %H:%M:%S"),
                    count=backoff.get('count')
                ))
        if len(out):
            return "".join(out)
    login_backoff.allow_tags = True

badgr_admin.register(BadgeUser, BadgeUserAdmin)


class EmailAddressVariantAdmin(ModelAdmin):
    search_fields = ('canonical_email', 'email',)
    list_display = ('email', 'canonical_email',)
    raw_id_fields = ('canonical_email',)

badgr_admin.register(EmailAddressVariant, EmailAddressVariantAdmin)


class TermsVersionAdmin(ModelAdmin):
    list_display = ('version','created_at','is_active')
    readonly_fields = ('created_at','created_by','updated_at','updated_by', 'latest_terms_version')
    fieldsets = (
        ('Metadata', {
            'fields': ('created_at','created_by','updated_at','updated_by'),
            'classes': ('collapse',)
        }),
        (None, {'fields': (
            'latest_terms_version', 'is_active','version','short_description',
        )})
    )

    def latest_terms_version(self, obj):
        return TermsVersion.cached.latest_version()
    latest_terms_version.short_description = "Current Terms Version"

badgr_admin.register(TermsVersion, TermsVersionAdmin)


class RecipientIdentifierAdmin(ModelAdmin):
    list_display = ('type', 'identifier', 'user', 'verified')
    list_filter = ('type', 'verified',)
    search_fields = ('identifier', 'user__email')
    raw_id_fields = ('user',)


badgr_admin.register(UserRecipientIdentifier, RecipientIdentifierAdmin)
