Usage:
# provide xml or directory path to debug script failure reason
./test.py <*.xml> or <Dir> 

# use -ca option, to check the corrective actions against the reported errors
./test.py -ca <*.xml> or <Dir> 

# use -cat option, to check the corrective actions against the reported errors stored in text file name robot_failure_suggestions.txt
# robot_failure_suggestions.txt -> this file is generated whenever the debugger script(test.py) is executed.
./test.py -cat robot_failure_suggestions.txt


``` 
12-15:/homes/surajsharma/ROBOT_LOG_PARSER> ./test.py 
Python3 path set to: /bin/python3
usage: test.py [-h] [-ca xml_file] [-cat log_file_path] [-ge] [paths [paths ...]]

Process XML or failure logs and optionally display corrective actions.

positional arguments:
  paths                File or directory paths to process

optional arguments:
  -h, --help           show this help message and exit
  -ca xml_file         Specify an XML file path or directory to enable corrective actions check
  -cat log_file_path   Specify a log file path in txt format for displaying corrective actions only
  -ge, --group-errors  Group errors by failure group to consolidate suggestions
12-15:/homes/surajsharma/ROBOT_LOG_PARSER> ./test.py <*.xml> or <Dir./>
```
