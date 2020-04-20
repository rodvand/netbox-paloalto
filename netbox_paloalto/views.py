from django.shortcuts import render
from django.views.generic import View
from .models import FirewallConfig

class FirewallRulesView(View):
    """
    Display the firewall rules related to the object
    """
    def get(self, request, name = None):
        if name:
            # Find all firewall rules
            import pandevice
            import pandevice.firewall
            import pandevice.policies
            import pandevice.objects

            fw_configs = FirewallConfig.objects.all()
            output = []

            for fw in fw_configs:
                hostname = fw.hostname
                api_key = fw.api_key

                fw_info = {}

                fw = pandevice.firewall.Firewall(hostname, api_key=api_key)
                all_objects = pandevice.objects.AddressGroup.refreshall(fw)
                search_term = []
                search_term.append(name)
                
                for obj in all_objects:
                    if name in obj.static_value:
                        search_term.append(obj.name)

                rulebase = pandevice.policies.Rulebase()

                fw.add(rulebase)

                sec_rules = pandevice.policies.SecurityRule.refreshall(rulebase)
                rules = []
                for rule in sec_rules:
                    for search in search_term:
                        if search in rule.source or search in rule.destination:
                            rules.append(rule)

                fw_info['search_term'] = search_term
                fw_info['hostname'] = hostname
                fw_info['found_rules'] = rules
                fw_info['total_rules'] = len(sec_rules)

                output.append(fw_info)

        return render(request, 'netbox_paloalto/rules.html', {
            'output': output,
            'name' : name
        })
