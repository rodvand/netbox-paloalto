# Palo Alto Networks firewall/Panorama NetBox plugin

This plugin enables you to list firewall rules defined on your Palo Alto Networks firewall or Panorama management server directly in Netbox. The URL `<NETBOX>/plugin/paloalto/<object>` will list all firewall rules associated with object (see limitations further down).

## Preview
![Plugin preview](docs/media/preview.png "Preview of the plugin")

## Compatibility
Netbox 2.8 and higher.

## Installation
```
pip3 install netbox-paloalo
```

Add you firewall/Panorama (can have multiple) through the Admin GUI of NetBox.

### Required settings
Assume a NetBox object with name Server01 and IP 1.2.3.4.

Available settings in PLUGINS_CONFIG is:
```
transform: True/False - Netbox object is transformed before the search in Panorama/firewall. 
                        Additional search term will be Server01.3.4.
```

## Generate your Palo Alto firewall API key
See [Palo Alto Networks documentation](https://docs.paloaltonetworks.com/pan-os/9-0/pan-os-panorama-api/get-started-with-the-pan-os-xml-api/get-your-api-key.html) on generating your API key.

## Limitations
* Only one nesting for address groups
* Does not include "any" rules based on zones (as we can't tell the zone from the object name)
* Does not match with subnet rules (you can have a rule saying 10.0.0.0/8 is allowed, but your object with the address 10.1.1.1 is not listed)
* Does currently not support other rule types than security rules (no NAT/Decryption/etc)
