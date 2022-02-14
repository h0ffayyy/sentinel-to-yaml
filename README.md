# sentinel-to-yaml

A simple script that converts exported Microsoft Sentinel analytics rules ARM template files to YAML format following the Microsoft Sentinel content [query style guide](https://github.com/Azure/Azure-Sentinel/wiki/Query-Style-Guide)


# Requirements

Only additional library requirement is PyYAML

# How to use

## Export analytics rules

This currently only works with the ARM templates exported from the web interface

## Running the script

Clone the repository: `git clone https://github.com/h0ffayyy/sentinel-to-yaml.git`

Install the required libraries: `pip install -r requirements.txt`

## Script help output

```
usage: s2y.py [-h] [-f FILE] [-d DIRECTORY] [-o OUTPUT]

Convert exported Microsoft Sentinel rules to YAML

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  the source file to convert to YAML
  -d DIRECTORY, --directory DIRECTORY
                        a source directory containing Sentinel rule files to convert to YAML
  -o OUTPUT, --output OUTPUT
                        specify a custom output directory

```

## Examples

### Convert a single file

`python s2y.py -f ./hafnium.json`

`python s2y.py --file ./hafnium.json`

### Convert a directory of files

`python s2y.py -d /home/h0ffayyy/sentinel-rules/input/`

`python s2y.py --directory /home/h0ffayyy/sentinel-rules/input/`

### Send converted files to a custom directory

`python s2y.py --directory /home/h0ffayyy/sentinel-rules/input/ -o converted_rules`

# Known Issues

- The `requiredDataConnector` field is set to an open brace by default
- Query output may get messed up if there is any weird whitespace