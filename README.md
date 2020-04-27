# Palo Alto Networks firewall plugin

This plugin enables you to list firewall rules defined on your Palo Alto Networks firewall or Panorama management server directly in Netbox.

## Compatibility
Netbox 2.8 and higher.

## Installation
To come

### Required settings
To come

## Generate your Palo Alto firewall API key
See [Palo Alto Networks documentation](https://docs.paloaltonetworks.com/pan-os/9-0/pan-os-panorama-api/get-started-with-the-pan-os-xml-api/get-your-api-key.html) on generating your API key.

## Constraints
* Only one nesting for address groups
* Does not include "any" rules based on zones (as we can't tell the zone from the object name)
* Does not match with subnet rules (you can have a rule saying 10.0.0.0/8 is allowed, but your object with the address 10.1.1.1 is not listed)
* Does currently not support other rule types than security rules (no NAT/Decryption/etc)
