#!/usr/bin/env python3

import argparse
import pathlib
import json
import yaml
import sys
import re


class SentinelRule():

    def __init__(self, rules_source):
        self.parsed_rules = []
        self.rules_source = rules_source


    def parse_sentinel_rule(self):
        json_data = json.load(self.rules_source)
        
        # handle ARM template rules
        if "$schema" in json_data:
            for rule in json_data['resources']:
                if 'displayName' not in rule['properties']:
                    continue

                rule_name = rule['properties']['displayName']
                rule_description = rule['properties']['description']
                rule_severity = rule['properties']['severity']
                rule_query = re.sub(r"[\r\t\s]+\n", "\n", rule['properties']['query'])
                rule_query_frequency = rule['properties']['queryFrequency'].replace("P", "").replace("T", "").lower()
                rule_query_period = rule['properties']['queryPeriod'].replace("P", "").replace("T", "").lower()
                rule_guid = rule['name'].split('SecurityInsights/')[1].split("\')]")[0] 
                rule_trigger_threshold = rule['properties']['triggerThreshold']
                rule_kind = rule['kind']
                rule_tactics = []

                if 'triggerOperator' in rule['properties']:
                    trigger_operator = self.parse_trigger_operator(rule['properties']['triggerOperator'])
                else:
                    trigger_operator = ""

                if len(rule['properties']['tactics']) > 0:
                    for tactic in rule['properties']['tactics']:
                        rule_tactics.append(tactic)

                rule_techniques = []
                if len(rule['properties']['techniques']) > 0:
                    for technique in rule['properties']['techniques']:
                        rule_techniques.append(technique)

                rule_required_connectors = []

                rule_entity_mappings = []
                if 'entityMappings' in rule['properties'] and rule['properties']['entityMappings'] is not None:
                    for entity in rule['properties']['entityMappings']:
                        rule_entity_mappings.append(entity)

                if 'templateVersion' in rule['properties']:
                    rule_template_version = rule['properties']['templateVersion']
                else:
                    rule_template_version = '1.0.0'

                parsed_rule = {
                    'id': f'{rule_guid}',
                    'name': f'{rule_name}', 
                    'description': f'{rule_description}',
                    'severity': f'{rule_severity}', 
                    'requiredDataConnectors': rule_required_connectors,
                    'queryFrequency': f'{rule_query_frequency}',
                    'queryPeriod': f'{rule_query_period}',
                    'triggerOperator': f'{trigger_operator}',
                    'triggerThreshold': rule_trigger_threshold,
                    'tactics': rule_tactics,
                    'relevantTechniques': rule_techniques,
                    'query': f"{rule_query}",
                    'entityMappings': rule_entity_mappings,
                    'version': rule_template_version,
                    'kind': f'{rule_kind}'
                }
                self.parsed_rules.append(parsed_rule)
        # handle az cli exported rules
        else:
            for rule in json_data:
                if 'displayname' not in rule:
                    continue

                rule_name = rule['displayName']
                rule_description = rule['description']
                rule_severity = rule['severity']
                rule_query = re.sub(r"[\r\t\s]+\n", "\n", rule['query'])
                rule_guid = rule['name']
                rule_trigger_threshold = rule['triggerThreshold']
                rule_kind = rule['kind']
                rule_tactics = []

                if 'triggerOperator' in rule:
                    trigger_operator = self.parse_trigger_operator(rule['triggerOperator'])
                else:
                    trigger_operator = ""

                if len(rule['tactics']) > 0:
                    for tactic in rule['tactics']:
                        rule_tactics.append(tactic)

                rule_query_period = self.parse_cli_time(rule['queryPeriod'])
                rule_query_frequency = self.parse_cli_time(rule['queryFrequency'])

                # az cli doesn't currently output techniques
                rule_techniques = []
                # az cli doesn't currently output connectors
                rule_required_connectors = []

                # az cli doesn't currently output entity mappings
                rule_entity_mappings = []

                # az cli doesn't currently output template versions
                rule_template_version = '1.0.0'

                parsed_rule = {
                    'id': f'{rule_guid}',
                    'name': f'{rule_name}', 
                    'description': f'{rule_description}',
                    'severity': f'{rule_severity}', 
                    'requiredDataConnectors': rule_required_connectors,
                    'queryFrequency': f'{rule_query_frequency}',
                    'queryPeriod': f'{rule_query_period}',
                    'triggerOperator': f'{trigger_operator}',
                    'triggerThreshold': rule_trigger_threshold,
                    'tactics': rule_tactics,
                    'relevantTechniques': rule_techniques,
                    'query': f"{rule_query}",
                    'entityMappings': rule_entity_mappings,
                    'version': rule_template_version,
                    'kind': f'{rule_kind}'
                }

                self.parsed_rules.append(parsed_rule)


    def parse_trigger_operator(self, operator):
        if operator == "GreaterThan":
            rule_trigger_operator = "gt"
        elif operator == "LessThan":
            rule_trigger_operator == "lt"
        elif operator == "Equal":
            rule_trigger_operator == "eq"
        else:
            rule_trigger_operator == ""

        return rule_trigger_operator


    def parse_cli_time(self, timevalue):
        if "day" in timevalue:
            formatted_time_value = timevalue.split(" day")[0] + "d"
        else:
            rule_hours = timevalue.split(":")[0]
            rule_minutes = timevalue.split(":")[1]

            if rule_hours != "0":
                formatted_time_value = rule_hours + "h"
            else:
                formatted_time_value = rule_minutes + "m"

        return formatted_time_value


def str_presenter(dumper, data):
    if len(data.splitlines()) > 1:
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
    return dumper.represent_scalar('tag:yaml.org,2002:str', data)


def create_yaml(rules, args):
    default_output_dir = pathlib.Path("./output")
    output_dir = default_output_dir

    if args.output is None and default_output_dir.is_dir() is False:
        default_output_dir.mkdir(exist_ok=True)
        output_dir = default_output_dir

    if args.output is not None:
        output_dir = args.output

        if args.output.is_dir() is False:
            args.output.mkdir(exist_ok=True)

    for rule in rules.parsed_rules:
        filename = re.sub("[^0-9a-zA-Z]+", "", rule['name'])
        with open(f"{output_dir}/{filename}.yml", "w") as target_file:
            data = yaml.dump(rule, target_file, sort_keys=False)


def parse_arguments():
    parser = argparse.ArgumentParser(prog='s2y.py', 
                                    description='Convert exported Microsoft Sentinel rules to YAML')
    parser.add_argument('-f', '--file', type=argparse.FileType('r'), 
                        help='the source file to convert to YAML')
    parser.add_argument('-d', '--directory', type=pathlib.Path, 
                        help='a source directory containing Sentinel rule files to convert to YAML')
    parser.add_argument('-o', '--output', type=pathlib.Path,
                        help='specify a custom output directory')
    args = parser.parse_args()

    if args.file is None and args.directory is None:
        print('[!] Please provide a source to convert to YAML')
        sys.exit(1)
    else:
        return args


def main():

    args = parse_arguments()

    if args.file is not None:
        SR = SentinelRule(args.file)
        SR.parse_sentinel_rule()
        create_yaml(SR, args)
    
    if args.directory is not None:
        for file in args.directory.glob('*.json'):
            SR = SentinelRule(file.open())
            SR.parse_sentinel_rule()
            create_yaml(SR, args)


if __name__ == "__main__":
    yaml.add_representer(str, str_presenter)
    yaml.representer.SafeRepresenter.add_representer(str, str_presenter)

    try:
        main()
    except KeyboardInterrupt:
        print('Execution interrupted!')
