from django.contrib.admin import ModelAdmin
from mainsite.admin import badgr_admin
from .models import Saml2Configuration, Saml2Account

class Saml2ConfigurationModelAdmin(ModelAdmin):
    model = Saml2Configuration

class Saml2AccountModelAdmin(ModelAdmin):
    model = Saml2Account

badgr_admin.register(Saml2Configuration, Saml2ConfigurationModelAdmin)
badgr_admin.register(Saml2Account, Saml2AccountModelAdmin)