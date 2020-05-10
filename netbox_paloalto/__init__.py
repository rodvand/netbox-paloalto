try:
    from extras.plugins import PluginConfig
except ImportError:
    # Dummy for when importing outside of netbox
    class PluginConfig:
        pass

VERSION = '0.3.0'


class PaloaltoConfig(PluginConfig):
    name = 'netbox_paloalto'
    verbose_name = 'Palo Alto firewall rules'
    description = 'A plugin for listing associated firewall rules to a NetBox object'
    version = VERSION
    author = 'Martin Rødvand'
    author_email = 'martin@rodvand.net'
    base_url = 'paloalto'
    required_settings = []
    default_settings = {}
    caching_config = {
        '*': None
    }


config = PaloaltoConfig
