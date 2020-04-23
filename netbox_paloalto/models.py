from django.db import models


class FirewallConfig(models.Model):
    """
    Holds configuration about Palo Alto firewall objects.
    Could be a device firewall, or Panorama
    """

    hostname = models.CharField(max_length=50)
    api_key = models.CharField(max_length=255)
    panorama = models.BooleanField()

    def __str__(self):
        return self.hostname
