# Registry-Scanner
Scan registry by providing hive files exported from regedit.
## reader.py
Performs a few scans for common malware locations for manual analysis. Scans for executables and similar files in the registry. An option is provided to use the VirusTotal API which allows those files to be retrieved if analysis was already completed or queue them for analysis. A SQL database and text file are the outputs for the script.
## find.py
Search the registry with provided search terms and/or range of dates (start and end). Output is a SQL database of the results of the scan.
