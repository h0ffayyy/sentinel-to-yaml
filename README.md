# sentinel-to-yaml

A simple script that converts exported Microsoft Sentinel analytics rules JSON files to YAML format following the [query style guide](https://github.com/Azure/Azure-Sentinel/wiki/Query-Style-Guide)


# Requirements
See `requirements.txt`

Only additional library requirement is PyYAML


# How to use
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

## Convert a single file

`python s2y.py -f ./hafnium.json`

`python s2y.py --file ./hafnium.json`

## Convert a directory of files

`python s2y.py -d /home/h0ffayyy/sentinel-rules/input/`

`python s2y.py --directory /home/h0ffayyy/sentinel-rules/input/`
## Send converted files to a custom directory

`python s2y.py --directory /home/h0ffayyy/sentinel-rules/input/ -o converted_rules`