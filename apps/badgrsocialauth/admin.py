from django.contrib.admin import ModelAdmin
from mainsite.admin import badgr_admin
from .models import Saml2Configuration, Saml2Account


class Saml2ConfigurationModelAdmin(ModelAdmin):
    model = Saml2Configuration
    readonly_fields = ('acs_url', 'sp_metadata_url')
    fields = ('metadata_conf_url', 'cached_metadata', 'slug', 'acs_url', 'sp_metadata_url', 'use_signed_authn_request',)
badgr_admin.register(Saml2Configuration, Saml2ConfigurationModelAdmin)


class Saml2AccountModelAdmin(ModelAdmin):
    raw_id_fields = ('user',)
    model = Saml2Account
badgr_admin.register(Saml2Account, Saml2AccountModelAdmin)
