from extras.plugins import PluginConfig

class PaloaltoConfig(PluginConfig):
    name = 'netbox_paloalto'
    verbose_name = 'Palo Alto firewall rules'
    description = 'A plugin for listing associated firewall rules to a NetBox object'
    version = '0.1'
    author = 'Martin Rødvand'
    author_email = 'martin@rodvand.net'
    base_url = 'paloalto'
    required_settings = []
    default_settings = {}
    caching_config = {
            '*': None
            }

config = PaloaltoConfig
