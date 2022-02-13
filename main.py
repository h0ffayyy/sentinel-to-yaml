import json
import yaml
import os
import re


class SentinelRule():

    def __init__(self, rules_source):
        self.parsed_rules = []
        self.rules_source = rules_source


    def parse_sentinel_rule(self):
        json_data = json.load(self.rules_source)
        
        for rule in json_data['resources']:
            rule_name = rule['properties']['displayName']
            rule_description = rule['properties']['description']
            rule_severity = rule['properties']['severity']
            rule_query = rule['properties']['query']
            rule_query_frequency = rule['properties']['queryFrequency'].replace("P", "").replace("T", "").lower()
            rule_query_period = rule['properties']['queryPeriod'].replace("P", "").replace("T", "").lower()
            rule_guid = rule['name'].split('SecurityInsights/')[1].split("\')]")[0] 
            rule_trigger_threshold = rule['properties']['triggerThreshold']
            rule_kind = rule['kind']
            rule_tactics = []

            if len(rule['properties']['tactics']) > 0:
                for tactic in rule['properties']['tactics']:
                    rule_tactics.append(tactic)

            rule_techniques = []
            if len(rule['properties']['techniques']) > 0:
                for technique in rule['properties']['techniques']:
                    rule_techniques.append(technique)

            rule_trigger_operator = rule['properties']['triggerOperator']
            if rule_trigger_operator == "GreaterThan":
                rule_trigger_operator = "gt"
            elif rule_trigger_operator == "LessThan":
                rule_trigger_operator == "lt"
            elif rule_trigger_operator == "Equal":
                rule_trigger_operator == "eq"

            rule_entity_mappings = []
            for entity in rule['properties']['entityMappings']:
                rule_entity_mappings.append(entity)

            if 'templateVersion' in rule['properties']:
                rule_template_version = rule['properties']['templateVersion']
            else:
                rule_template_version = '1.0.0'
                                
            parsed_rule = {'id': f'{rule_guid}',
                                'name': f'{rule_name}', 
                                'description': f'{rule_description}',
                                'severity': f'{rule_severity}', 
                                'queryFrequency': f'{rule_query_frequency}',
                                'queryPeriod': f'{rule_query_period}',
                                'triggerOperator': f'{rule_trigger_operator}',
                                'triggerThreshold': rule_trigger_threshold,
                                'tactics': rule_tactics,
                                'relevantTechniques': rule_techniques,
                                'query': f"{rule_query}",
                                'entityMappings': rule_entity_mappings,
                                'version': rule_template_version,
                                'kind': f'{rule_kind}'
                                }
            self.parsed_rules.append(parsed_rule)


def str_presenter(dumper, data):
    if len(data.splitlines()) > 1:
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
    return dumper.represent_scalar('tag:yaml.org,2002:str', data)


def create_yaml(rules):
    for rule in rules.parsed_rules:
        filename = re.sub("[^0-9a-zA-Z]+", "", rule['name'])
        with open(f"output/{filename}.yml", "w") as target_file:
            data = yaml.dump(rule, target_file, sort_keys=False)


def main():
    rules_source = open("./hafnium.json", "r")
    #rules_source = open("./linux-failed-logins.json", "r")
    #rules_source = open("./privileged_role.json", "r")

    SR = SentinelRule(rules_source)
    SR.parse_sentinel_rule()

    create_yaml(SR)


if __name__ == "__main__":
    yaml.add_representer(str, str_presenter)
    yaml.representer.SafeRepresenter.add_representer(str, str_presenter)
    main()
