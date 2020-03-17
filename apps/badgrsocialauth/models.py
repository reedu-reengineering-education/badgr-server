from django.db import models
from badgeuser.models import BadgeUser

class Saml2Configuration(models.Model):
    metadata_conf_url = models.URLField(verbose_name="Metadata Configuration URL", help_text="The URL for the XML configuration for SAML2 flows. Get this from the Identity Provider Application.")
    cached_metadata = models.TextField(default='', blank=True, help_text="If the XML is provided here we avoid making a network request to the metadata_conf_url.")
    slug = models.CharField(max_length=32, unique=True, help_text="This slug must be prefixed with saml2.")

    def __str__(self):
        return self.slug

class Saml2Account(models.Model):
    user = models.ForeignKey(BadgeUser)
    config = models.ForeignKey(Saml2Configuration)
    uuid = models.CharField(max_length=255, unique=True)

    def __str__(self):
        return "{} on {}".format(self.uuid, self.config)