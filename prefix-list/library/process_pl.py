#!/usr/bin/env python3

import netaddr
import collections
import re
import yaml
from ansible.module_utils.basic import *

def process_original(raw_list):

    pl_list = []
    pl_names_dict = {}
    pl_dict = collections.defaultdict(list)
    pl_dict_final = {}
    delete_list = []
    temporary_list = []
    pl_description_list = []
    pl_default_route = []
    pl_desc_dict = collections.defaultdict(list)
    pl_default_dict = collections.defaultdict(list)
    yaml_dict = {}
    split_list = []
    
    for line in raw_list:
        temporary_list = line.split() #SPLITTING LINES INTO LIST
        split_list.append(temporary_list)  #ADDING LIST TO LIST OF LIST
        temporary_list = [] #Reset TEMP List
        
    for i, line in enumerate(split_list): #Grab PL name and description and place them in pl_descripiton_list
        pl_names_dict[line[2]] = ''
        if line[3] == 'description':    # in a list of lists for further processing
            temporary_list.append(line[2]) 
            temporary_list.append(' '.join(line[4::]))
            pl_description_list.append(temporary_list)
            delete_list.append(line)
        if line [6] == '0.0.0.0/0': # Finds and removes default routes
            temporary_list.append(line[2]) 
            temporary_list.append(line[6])
            pl_default_route.append(temporary_list)
            delete_list.append(line)
        temporary_list = []

    for del_lines in delete_list: # CLEARS OUT DESCRIPTIONS & DEFAULT ROUTES
        split_list.remove(del_lines)

    for i, line in enumerate(split_list): # Grab PL name and network and place them
        temporary_list.append(line[2])    # in a list of lists for further processing
        temporary_list.append(line[6])
        pl_list.append(temporary_list)
        temporary_list = []

    for key, value in pl_description_list:  #create pl_desc_dict using the key and description string
        tempString = value
        pl_desc_dict[key] = tempString
    
    for key, value in pl_default_route:  #create pl_default_dict using the key and network
        pl_default_dict[key].append(netaddr.IPNetwork(value))

    for key, value in pl_list:  #create pl_dict using the key and network
        pl_dict[key].append(netaddr.IPNetwork(value))
   
    for key, value in pl_dict.items():
        value = netaddr.cidr_merge(value)
        value.sort()
        pl_dict_final[key] = value

    d = collections.OrderedDict(sorted(pl_names_dict.items()))
    
    yaml_dict['allowed'] = {}
    yaml_dict['remediation'] = {}

    for key, blank in d.items():
        if "ALLOWED" in key:
           m = re.findall('\d:\d{4}', key)
           if m:
                vrf = m
           yaml_dict['allowed'][vrf[0]] = {}
           if key in pl_desc_dict:
                yaml_dict['allowed'][vrf[0]]['description'] = pl_desc_dict[key]
           yaml_dict['allowed'][vrf[0]]['prefix'] = {}
           if key in pl_dict_final:
                temp_list = []
                for i, ip_address in enumerate(pl_dict_final[key]):
                    temp_list.append(str(ip_address))
                yaml_dict['allowed'][vrf[0]]['prefix'] = temp_list
        if "REMEDIATION" in key:
           m = re.findall('\d:\d{4}', key)
           if m:
                vrf = m
           yaml_dict['remediation'][vrf[0]] = {}
           if key in pl_desc_dict:
                yaml_dict['remediation'][vrf[0]]['description'] = pl_desc_dict[key]
           yaml_dict['remediation'][vrf[0]]['prefix'] = {}
           if key in pl_dict_final:
                temp_list = []
                for i, ip_address in enumerate(pl_dict_final[key]):
                    temp_list.append(str(ip_address))
                yaml_dict['remediation'][vrf[0]]['prefix'] = temp_list
         
    return yaml_dict
            
def process_new(original_yaml):
    
    remediation_vrfs = ['1:1200', '1:1500', '1:1600', '1:2100', '1:2600']
    output_dict = {}
    output_yaml = {}

    with open("pl_changes.yaml", 'r') as stream:
        try:
            change_yaml = yaml.load(stream)
        except yaml.YAMLError as exc:
            print(exc)

    temp_list = change_yaml['change_number']
    change_number = temp_list[0]

    for top_level_key, blank in change_yaml.items():
        if top_level_key == 'add':
            for list_type, blank in change_yaml[top_level_key].items():
                for vrf, blank in change_yaml[top_level_key][list_type].items():
                    temp_ip_set = netaddr.IPSet()
                    temp_list = change_yaml[top_level_key][list_type][vrf]
                    for i, ip_address in enumerate(temp_list):
                        temp_ip_set.add(ip_address)
                    for i, ip_address in enumerate(original_yaml[list_type][vrf]['prefix']):
                        temp_ip_set.add(ip_address)
                    temp_list = []
                    for i, ip_address in enumerate(temp_ip_set.iter_cidrs()):
                        temp_list.append(str(ip_address))
                    original_yaml[list_type][vrf]['prefix'] = temp_list
                    if list_type != 'remediation':
                        if vrf in remediation_vrfs:
                            remediation_required = True
                            for i, rem_vrf in enumerate(remediation_vrfs):
                                temp_ip_set = netaddr.IPSet()
                                if vrf != rem_vrf:
                                    temp_list = change_yaml[top_level_key][list_type][vrf]
                                    for i, ip_address in enumerate(temp_list):
                                        temp_ip_set.add(ip_address)
                                    for i, ip_address in enumerate(original_yaml['remediation'][rem_vrf]['prefix']):
                                        temp_ip_set.add(ip_address)
                                    temp_list = []
                                    for i, ip_address in enumerate(temp_ip_set.iter_cidrs()):
                                        temp_list.append(str(ip_address))
                                    original_yaml['remediation'][rem_vrf]['prefix'] = temp_list

        if top_level_key == 'remove':
            for list_type, blank in change_yaml[top_level_key].items():
                for vrf, blank in change_yaml[top_level_key][list_type].items():
                    temp_ip_set = netaddr.IPSet()
                    temp_list = change_yaml[top_level_key][list_type][vrf]
                    for i, ip_address in enumerate(original_yaml[list_type][vrf]['prefix']):
                        temp_ip_set.add(ip_address)
                    for i, ip_address in enumerate(temp_list):
                        temp_ip_set.remove(ip_address)
                    temp_list = []
                    for i, ip_address in enumerate(temp_ip_set.iter_cidrs()):
                        temp_list.append(str(ip_address))
                    original_yaml[list_type][vrf]['prefix'] = temp_list
                    if list_type != 'remediation':
                        if vrf in remediation_vrfs:
                            for i, rem_vrf in enumerate(remediation_vrfs):
                                temp_ip_set = netaddr.IPSet()
                                if vrf != rem_vrf:
                                    temp_list = change_yaml[top_level_key][list_type][vrf]
                                    for i, ip_address in enumerate(original_yaml['remediation'].get(rem_vrf)['prefix']):
                                        temp_ip_set.add(ip_address)
                                    for i, ip_address in enumerate(temp_list):
                                        temp_ip_set.remove(ip_address)
                                    temp_list = []
                                    for i, ip_address in enumerate(temp_ip_set.iter_cidrs()):
                                        temp_list.append(str(ip_address))
                                    original_yaml['remediation'][rem_vrf]['prefix'] = temp_list
            
    return original_yaml
     
def main():
  
    module = AnsibleModule(
            argument_spec=dict(
                prefix_list = dict(required=True, type='list'),
                success = dict(default=True, type='bool'),
            ),
            supports_check_mode=True
        )

    original_prefix_list = module.params['prefix_list']
    success = module.params['success']
    original_yaml_dict = process_original(original_prefix_list)
    final_prefix_list_yaml = process_new( original_yaml_dict)
        
    if success:
      module.exit_json(finallist=final_prefix_list_yaml)
    else:
      module.fail_json(msg=success)
            
     

if __name__ == "__main__":
    main()
