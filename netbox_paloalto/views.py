from django.shortcuts import render, redirect
from django.views.generic import View
from dcim.models import Device
from virtualization.models import VirtualMachine
from .models import FirewallConfig
from netbox_paloalto import config
import netbox.settings


class FirewallRulesView(View):
    def search_objects(self, all_objects, current_search, nest_level=1, previous=None):
        if not previous:
            search_list = current_search
        else:
            if previous == current_search:
                search_list = current_search
            else:
                search_list = list(set(previous) - set(current_search))

        for adr_object in all_objects:
            move_on = False
            if not adr_object.static_value:
                continue
            for member in adr_object.static_value:
                for name in current_search:
                    if member.lower() == name.lower():
                        search_list.append(adr_object.name)
                        move_on = True
                        break
                if move_on:
                    break

        setting = netbox.settings.PLUGINS_CONFIG['netbox_paloalto']
        if 'netsing' in setting and nest_level < setting['nesting']:
            nest_level += 1
            return self.search_objects(all_objects, search_list, nest_level, current_search)

        search_list.extend(current_search)
        return search_list

    def return_search_terms(self, all_objects, obj):
        search_list = []
        search_list.append(obj.name)
        setting = netbox.settings.PLUGINS_CONFIG['netbox_paloalto']

        if 'transform' in setting and setting['transform']:
            ip = str(obj.primary_ip4.address.ip)
            last_octets = ".".join(ip.split('.')[2:4])
            name = "{}.{}".format(obj.name, last_octets)
            search_list.append(name)

        return self.search_objects(all_objects, search_list)

    @staticmethod
    def find_matching_rules(search_rules, search_terms):
        found_rules = []
        for rule in search_rules:
            for search in search_terms:
                if search in rule.source or search in rule.destination:
                    found_rules.append(rule)

        return list(set(found_rules))

    def post(self, request):
        if request.POST:
            name = request.POST.get('name')
            return redirect('plugins:netbox_paloalto:firewall_rule', name=name)

        return render(request, 'netbox_paloalto/rules.html')

    """
    Display the firewall rules related to the object
    """
    def get(self, request, name=None):
        if not name:
            return render(request, 'netbox_paloalto/rules.html')
        if name:
            # Check if we have a valid Device og VirtualMachine object
            try:
                obj = Device.objects.get(name=name)
            except Device.DoesNotExist as e:
                error = str(e)
                try:
                    obj = VirtualMachine.objects.get(name=name)
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
                        error = str(e)
                        error_heading = 'Unable to establish connection with Panorama {}'.format(name)
                        error_body = 'Check credentials/network connection before trying again.'

                        return render(request, 'netbox_paloalto/rules.html', {
                            'name': name,
                            'error': error,
                            'error_heading': error_heading,
                            'error_body': error_body})
                else:
                    firew = pandevice.firewall.Firewall(fw.hostname, api_key=fw.api_key)

                if fw.panorama:
                    search_objects = []
                    for group in dg:
                        all_objects = pandevice.objects.AddressGroup.refreshall(group)
                        search_term = self.return_search_terms(all_objects, obj)
                        search_term = list(set(search_term))
                        search_objects.extend(search_term)

                    search_objects = list(set(search_objects))

                    for group in dg:
                        fw_info = {}

                        pre = pandevice.policies.PreRulebase()
                        post = pandevice.policies.PostRulebase()
                        group.add(pre)
                        group.add(post)

                        rules = pandevice.policies.SecurityRule.refreshall(pre)
                        rules += pandevice.policies.SecurityRule.refreshall(post)

                        found_rules = self.find_matching_rules(rules, search_objects)

                        fw_info['search_term'] = search_objects
                        fw_info['panorama'] = fw.panorama
                        fw_info['hostname'] = fw.hostname
                        fw_info['device_group'] = group.name
                        fw_info['found_rules'] = found_rules
                        fw_info['total_rules'] = len(rules)

                        if len(found_rules) > 0:
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

                    search_term = self.return_search_terms(all_objects, obj)
                    search_term = list(set(search_term))

                    rulebase = pandevice.policies.Rulebase()
                    firew.add(rulebase)
                    sec_rules = pandevice.policies.SecurityRule.refreshall(rulebase)

                    rules = self.find_matching_rules(sec_rules, search_term)

                    fw_info['search_term'] = search_term
                    fw_info['panorama'] = fw.panorama
                    fw_info['hostname'] = fw.hostname
                    fw_info['device_group'] = None
                    fw_info['found_rules'] = rules
                    fw_info['total_rules'] = len(sec_rules)

                    if len(rules) > 0:
                        output.append(fw_info)

        return render(request, 'netbox_paloalto/rules.html', {
            'output': output,
            'name': name
        })
