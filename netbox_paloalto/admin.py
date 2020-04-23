from django.contrib import admin
from .models import FirewallConfig


@admin.register(FirewallConfig)
class FirewallConfigAdmin(admin.ModelAdmin):
    list_display = ('hostname', 'api_key', 'panorama')
