import pandevice
import pandevice.firewall
import pandevice.policies

hostname = 'vpn.rodvand.net'

username = 'netbox'
password = 'ict-mas-krur-tir'

fw = pandevice.firewall.Firewall(hostname, username, password)

rulebase = pandevice.policies.Rulebase()

fw.add(rulebase)

current_security_rules = pandevice.policies.SecurityRule.refreshall(rulebase)

for rule in current_security_rules:
        print('- {0}'.format(rule.name))
