from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json
import re
import oyaml as yaml
from collections import OrderedDict, deque

from ansible.module_utils.six import iteritems
from ansible.plugins.action import ActionBase
from ansible.errors import AnsibleActionFail
from ansible.module_utils.connection import Connection


def generate_documentation(attribute_map_by_param, json_payload, parent_module, module_info, module_version):
    def doc_option_generator(json_payload, temp_payload):
        for k, v in iteritems(json_payload):
            if isinstance(v, dict):
                for key, val in iteritems(v):
                    if 'type' in val and dict(val)['type'] != 'array':
                        if val['type'] == 'string':
                            temp_payload[key] = {'type': 'str'}
                        if val['type'] == 'integer':
                            temp_payload[key] = {'type': 'int'}
                        if val['type'] == 'boolean':
                            temp_payload[key] = {'type': 'bool'}
                        if val.get('description') and temp_payload.get(key) and not temp_payload[key].get('description'):
                            val_description = re.sub("`", "'", val['description'])
                            val_description = re.sub("'\\n'", "'\\\\n'", val_description)
                            temp = {'description': val_description}
                            temp.update(temp_payload[key])
                            temp_payload[key] = temp
                        if val.get('enum') and not temp_payload[key].get('choices'):
                            temp_payload[key].update({'choices': val['enum']})
                    if 'type' in val and dict(val)['type'] == 'array' and 'items' in val and 'type' in dict(val)['items']:
                        temp_payload[key] = {'type': 'list'}
                        if val['items']['type'] == 'string':
                            temp_payload[key].update({'elements': 'str'})
                        elif val['items']['type'] == 'integer':
                            temp_payload[key].update({'elements': 'int'})
                        if val.get('enum'):
                            temp_payload[key].update({'choices': val['enum']})
                        if val.get('description') and not temp_payload[key].get('description'):
                            val_description = re.sub("`", "'", val['description'])
                            val_description = re.sub("'\\n'", "'\\\\\\n'", val_description)
                            temp = {'description': val_description}
                            temp.update(temp_payload[key])
                            temp_payload[key] = temp
                        if val.get('enum') and not temp_payload[key].get('choices'):
                            temp_payload[key].update({'choices': val['enum']})
                    elif 'type' in val and dict(val)['type'] == 'list' and 'suboptions' in val and isinstance(dict(val)['suboptions'], dict):
                        if val.get('description') and not temp_payload[key].get('description'):
                            val_description = re.sub("`", "'", val['description'])
                            val_description = re.sub("'\\n'", "'\\\\n'", val_description)
                            temp = {'description': val_description}
                            temp.update(temp_payload[key])
                            temp_payload[key] = temp
                        if val.get('enum') and not temp_payload[key].get('choices'):
                            temp_payload[key].update({'choices': val['enum']})
                        temp_payload[key] = v[key]


    temp_json_payload = {}
    doc_option_generator(json_payload, temp_json_payload)
    module_description = ''
    if json_payload.get('description'):
        module_description = json_payload['description']
    if json_payload.get('properties'):
        json_payload = temp_json_payload
    module_name = parent_module + "_" + "_".join(module_info.lower().split(' '))
    module_obj = {
        "module": "{0}".format(module_name),
        "short_description": "Manages {0} resource module".format(module_info),
        "description": "{0}".format(module_description),
        "version_added": "{0}".format(module_version),
        "options": {
            "config": {
                "description": "A dictionary of Intrusion Prevention Rules options",
                "type": "list",
                "elements": "dict",
                "suboptions": json_payload,
            },
            "state": {
                "description": [
                    "The state the configuration should be left in",
                    "The state I(gathered) will get the module API configuration from the device and transform it into structured data in the format as per the module argspec and the value is returned in the I(gathered) key within the result."
                ],
                "type": "str",
                "choices": [
                    "merged",
                    "replaced",
                    "overridden",
                    "gathered",
                    "deleted"
                ]
            }
        },
        "author": "{0}".format("Ansible Security Automation Team (@justjais) <https://github.com/ansible-security>"),
    }
    json_obj = json.dumps(module_obj)
    with open('/Users/sjaiswal/Sumit/Self_Test/Basic/Ansible/data.yml', 'w+') as ff:
        yaml_obj = yaml.safe_load(json_obj)
        ydump = yaml.dump(yaml_obj)
        ff.write("""{0}""".format(ydump))

def convert_word_to_snake_case(word, global_var_mgmt_dict):
    upperc_only_word = None
    first_word = ''
    list_desc = re.compile("([A-Z]+[a-z]+|[A-Z][a-z]+|[A-Z]+)").findall(word)
    if list_desc:
        uppecase_word_len = word.split(re.compile("([A-Z]+)").findall(word)[0])
        if uppecase_word_len[0] != '':
            first_word_compile = re.compile("([a-z]+)").findall(word)
            if first_word_compile:
                first_word = first_word_compile[0] + "_"
            else:
                upperc_only_word = re.compile("([A-Z]+)").findall(word)[0].lower()
    else:
        first_word = word
    if upperc_only_word:
        test = upperc_only_word
    else:
        list_desc = map(lambda x: x.lower(), list_desc)
        test = first_word + "_".join(list_desc)
    if word != test and test not in global_var_mgmt_dict:
        global_var_mgmt_dict.update({test: word})
    return test

def gen_dict_extract(key, var):
    if isinstance(var,dict):
        for k, v in iteritems(var):
            if k == key:
                yield v
                break
            if isinstance(v, dict):
                for result in gen_dict_extract(key, v):
                    yield result

def get_api_param_properties(object, api_object, data):

    def get_api_object(schema_path, data):
        for each in schema_path:
            if each == '#':
                post_object = data
            else:
                post_object = OrderedDict(post_object[each])
        return post_object

    if 'properties' in api_object:
        return api_object
    post_schema_path = list(gen_dict_extract(object, api_object))[0].split('/')

    post_object = get_api_object(post_schema_path, data)

    for k, v in iteritems(post_object.get('properties')):
        if '$ref' in v:
            print(k, v, v['$ref'])
            inbound_1st_level_schema_path = v['$ref'].split('/')
            temp_k_properties = get_api_object(inbound_1st_level_schema_path, data)
            if temp_k_properties.get('properties'):
                del post_object['properties'][k]['$ref']
                post_object['properties'][k]["type"] = "array"
                post_object['properties'][k]["items"] = {inbound_1st_level_schema_path[-1]: temp_k_properties['properties']}
            else:
                post_object['properties'][k] = temp_k_properties
            if post_object['properties'][k].get('items') and isinstance(post_object['properties'][k]['items'], dict):
                temp_param_key = {}
                for key, val in iteritems(post_object['properties'][k]['items']):
                    if isinstance(val, dict):
                        for each_key, each_val in iteritems(val):
                            if '$ref' in each_val:
                                inbound_2nd_level_schema_path = each_val['$ref'].split('/')
                                temp_k_properties = get_api_object(inbound_2nd_level_schema_path, data)
                                if temp_k_properties.get('properties'):
                                    if temp_k_properties.get('type') == 'object':
                                        temp_k_properties['type'] = "array"
                                if key not in temp_param_key:
                                    temp_param_key.update({key: {each_key: dict(temp_k_properties['properties'])}})
                                else:
                                    temp_param_key[key].update({each_key: dict(temp_k_properties['properties'])})
                            else:
                                if key not in temp_param_key:
                                    temp_param_key[key].update({each_key: each_val})
                                else:
                                    temp_param_key[key].update({each_key: each_val})
                post_object['properties'][k] = temp_param_key

        elif 'items' in v and '$ref' in v['items']:
            print(k, v, v['items']['$ref'])
            inbound_schema_path = v['items']['$ref'].split('/')
            ref_object = get_api_object(inbound_schema_path, data)
            post_object['properties'][k]["items"] = {inbound_schema_path[-1]: ref_object}


    return get_api_param_properties('$ref', post_object, data)

def update_param_to_ansible_std(val, count=0):
    count += 1
    if val.get('type') == 'string':
        val['type'] = 'str'
    if val.get('type') == 'integer':
        val['type'] = 'int'
    if val.get('type') == 'boolean':
        val['type'] = 'bool'
    if val.get('type') == 'array':
        val['type'] = 'list'
        if 'type' in val.get('items'):
            if val['items']['type'] == 'string':
                val['elements'] = 'str'
            elif val['items']['type'] == 'integer':
                val['elements'] = 'int'
            del val['items']
    if val.get('format'):
        del val['format']
    if val.get('enum'):
        val['choices'] = val['enum']
        del val['enum']
    if val.get('title'):
        val['description'] = val['title']
        del val['title']

    return val, count

def get_api_param_properties_recursively(object, api_object, data, global_var_mgmt_dict):
    def get_api_object(schema_path, data):
        for each in schema_path:
            if each == '#':
                post_object = data
            else:
                post_object = OrderedDict(post_object[each])
        return post_object

    def recursive_stack_parse_ref(key, value, data, stack, parent_key_elements):
        if '$ref' in value or ('items' in value and '$ref' in value['items']):
            if '$ref' in value:
                stack.append("ref")
                path_url_split = dict(value)['$ref'].split('/')
            elif 'items' in value and '$ref' in value['items']:
                path_url_split = dict(v)['items']['$ref'].split('/')
            post_object = get_api_object(path_url_split, data)
            stack.append(path_url_split[-1])
            if post_object.get('properties'):
                #child_stack = deque()
                temp_post_object = {}
                temp = {}
                for each_k, each_v  in iteritems(post_object['properties']):
                    if (each_v.get('type') == 'array' and each_v.get('items')) or 'type' not in each_v:
                        temp.update({each_k: each_v})
                    else:
                        temp_post_object.update({each_k: each_v})
                if temp:
                    temp_post_object.update(temp)
                for each_k, each_v in iteritems(temp_post_object):
                    if each_v.get("$ref"):
                        stack.append("ref")
                    if 'type' not in each_v:
                        stack.append(each_k)
                        recursive_stack_parse_ref(each_k, each_v, data, stack, parent_key_elements)
                    elif each_v.get('type') == 'array' and each_v.get('items'):
                        stack.append(each_k)
                        recursive_stack_parse_ref(each_k, each_v['items'], data, stack, parent_key_elements)
                    elif each_k in parent_key_elements:
                        stack.append(each_k)
                        stack.append(each_v)
                    else:
                        stack.append({each_k: each_v})
            else:
                stack.append(post_object)

    if 'properties' in api_object:
        return api_object

    post_schema_path = list(gen_dict_extract(object, api_object))[0].split('/')

    post_object = get_api_object(post_schema_path, data)
    post_object_temp = None
    ref = False
    temp_post_object = {}
    if post_object.get('properties'):
        temp_post_object['properties'] = {}
        for k, v in iteritems(post_object['properties']):
            temp_k = convert_word_to_snake_case(k, global_var_mgmt_dict)
            temp_post_object['properties'][temp_k] = post_object['properties'][k]
            parent_key_elements = []
            final_dict = {}
            stack = deque()
            path_url_split = None
            if '$ref' in v:
                ref = True
                path_url_split = dict(v)['$ref'].split('/')
            if 'items' in v and '$ref' in v['items']:
                ref = True
                path_url_split = dict(v)['items']['$ref'].split('/')
            if path_url_split:
                post_object_temp = get_api_object(path_url_split, data)
                if not parent_key_elements and post_object_temp and post_object_temp.get('properties'):
                    parent_key_elements = list(post_object_temp['properties'])
                if 'name' in parent_key_elements:
                    parent_key_elements[parent_key_elements.index('name')] = 'name_parent'

            recursive_stack_parse_ref(k, v, data, stack, parent_key_elements)
            temp_key = None
            if stack:
                temp = {}
                temp_parent = []
                for each in parent_key_elements:
                    temp_parent.append(convert_word_to_snake_case(each, global_var_mgmt_dict))
                parent_key_elements = temp_parent
                check_dict = False
                count = 0
                previous = False
                for i in range(len(stack)):
                    val = stack.pop()
                    if i == len(stack) and val == 'ref':
                        continue
                    if val == 'ref':
                        previous = True
                        continue
                    if val == 'processPolicy':
                        print(val)
                    if val == 'split' and i == 0:
                        continue
                    if not isinstance(val, dict) and val not in parent_key_elements:
                        val = convert_word_to_snake_case(val, global_var_mgmt_dict)
                    if val in parent_key_elements:
                        if check_dict:
                            if temp.get('type'):
                                final_dict.update({val: temp})
                            else:
                                final_dict.update({val: {'type': 'dict', 'suboptions': temp}})
                        temp = {}
                        continue
                    elif isinstance(val, dict) and previous:
                        final_dict.update(temp)
                        previous = False
                        temp = {}
                    if isinstance(val, dict):
                        check_dict = True
                        val, count = update_param_to_ansible_std(val, count)
                        temp.update(val)
                    else:
                        count += 1
                        temp = {val: temp}
                    if previous:
                        temp_key = list(temp.keys())[0]
                        if temp_key != 'type':
                            if temp[temp_key].get('type') == 'array' or not temp[temp_key].get('type'):
                                temp[temp_key] = {'type': 'dict', 'suboptions': temp[temp_key]}
                        previous = False
                if temp and not final_dict:
                    final_dict = temp

            if final_dict:
                final_dict = OrderedDict(reversed(list(iteritems(final_dict))))
                temp_post_object['properties'][temp_k] = {'type': 'list', 'elements': 'dict', 'suboptions': {temp_key: final_dict}}
            elif ref and post_object_temp and path_url_split:
                temp_post_object['properties'][temp_k]['items'] = {path_url_split[-1]: post_object_temp}
    post_object['properties'] = temp_post_object['properties']
    return post_object

def main():
    print("Enter Main!!!!")
    with open('/Users/sjaiswal/Sumit/ansible_fork/collections/security_collections/doc_generator/swagger_tm.json') as file:
        print("Inside")
        json_content = file.read()
        data = json.loads(json_content, object_pairs_hook=OrderedDict)
        api_object = data["paths"]["/intrusionpreventionrules"]["post"]
        global_var_mgmt_dict = {}
        post_properties = get_api_param_properties_recursively("$ref", api_object, data, global_var_mgmt_dict)
        with open('/Users/sjaiswal/Sumit/Self_Test/Basic/Ansible/params.json', 'w+') as ff:
            ff.write("""{0}""".format(json.dumps(global_var_mgmt_dict)))
        temp = {}
        attribute_map_by_param = {}

        module_info = "Intrusion Prevention Rules"
        module_version = "2.0.0"
        parent_module = "deepsec"
        generate_documentation(attribute_map_by_param, post_properties, parent_module, module_info, module_version)

if __name__ == "__main__":
    main()