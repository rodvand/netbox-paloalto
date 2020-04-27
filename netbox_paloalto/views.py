from django.shortcuts import render
from django.views.generic import View
from dcim.models import Device
from virtualization.models import VirtualMachine
from .models import FirewallConfig


class FirewallRulesView(View):
    @staticmethod
    def return_search_terms(all_objects, name):
        search_list = []
        search_list.append(name)

        for obj in all_objects:
            if obj.static_value and name in obj.static_value:
                search_list.append(obj.name)

        return search_list

    @staticmethod
    def find_matching_rules(search_rules, search_terms):
        found_rules = []
        for rule in search_rules:
            for search in search_terms:
                if search in rule.source or search in rule.destination:
                    found_rules.append(rule)

        return found_rules

    """
    Display the firewall rules related to the object
    """
    def get(self, request, name=None):
        if name:
            # Check if we have a valid Device og VirtualMachine object
            try:
                device = Device.objects.get(name=name)
            except Device.DoesNotExist as e:
                error = str(e)
                try:
                    vm = VirtualMachine.objects.get(name=name)
                except VirtualMachine.DoesNotExist as e:
                    error += " "
                    error += str(e)
                    error_heading = 'Unable to find object {} in NetBox'.format(name)
                    error_body = 'Make sure the object exists in Netbox before trying again'

                    return render(request, 'netbox_paloalto/rules.html', {
                        'name': name,
                        'error': error,
                        'error_heading': error_heading,
                        'error_body': error_body})

            # Find all firewall rules
            import pandevice
            import pandevice.firewall
            import pandevice.panorama
            import pandevice.policies
            import pandevice.objects

            fw_configs = FirewallConfig.objects.all()
            output = []

            for fw in fw_configs:
                if fw.panorama:
                    # Dealing with Panorama
                    pano = pandevice.panorama.Panorama(fw.hostname, api_key=fw.api_key)
                    try:
                        dg = pandevice.panorama.DeviceGroup.refreshall(pano)
                    except Exception as e:
                        print(e)
                else:
                    firew = pandevice.firewall.Firewall(fw.hostname, api_key=fw.api_key)

                if fw.panorama:
                    for group in dg:
                        fw_info = {}
                        all_objects = pandevice.objects.AddressGroup.refreshall(group)
                        search_term = self.return_search_terms(all_objects, name)

                        pre = pandevice.policies.PreRulebase()
                        post = pandevice.policies.PostRulebase()
                        group.add(pre)
                        group.add(post)

                        rules = pandevice.policies.SecurityRule.refreshall(pre)
                        rules += pandevice.policies.SecurityRule.refreshall(post)

                        found_rules = self.find_matching_rules(rules, search_term)

                        fw_info['search_term'] = search_term
                        fw_info['panorama'] = fw.panorama
                        fw_info['hostname'] = fw.hostname
                        fw_info['device_group'] = group.name
                        fw_info['found_rules'] = found_rules
                        fw_info['total_rules'] = len(rules)
                        output.append(fw_info)
                else:
                    fw_info = {}
                    try:
                        all_objects = pandevice.objects.AddressGroup.refreshall(firew)
                    except pandevice.errors.PanURLError as e:
                        error_heading = 'Unable to connect properly to the firewall'
                        error = str(e)
                        error_body = 'Verify the hostname and API key of the firewall and try again.'

                        return render(request, 'netbox_paloalto/rules.html', {
                            'name': name,
                            'error': error,
                            'error_heading': error_heading,
                            'error_body': error_body})

                    search_term = self.return_search_terms(all_objects, name)

                    rulebase = pandevice.policies.Rulebase()
                    firew.add(rulebase)
                    sec_rules = pandevice.policies.SecurityRule.refreshall(rulebase)

                    rules = self.find_matching_rules(sec_rules, search_term)

                    fw_info['search_term'] = search_term
                    fw_info['panorama'] = fw.panorama
                    fw_info['hostname'] = hostname
                    fw_info['device_group'] = None
                    fw_info['found_rules'] = rules
                    fw_info['total_rules'] = len(sec_rules)

                    output.append(fw_info)

        return render(request, 'netbox_paloalto/rules.html', {
            'output': output,
            'name': name
        })
