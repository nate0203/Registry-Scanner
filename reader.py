"""
    reader.py
    Author: Nathan Ly

    Using Python Registry library, a scan is completed on the provided hive file to extract
    information about potential issues for the user.
"""
import argparse
import os
import sys
import requests
import datetime
import hashlib
import logging
import urllib3
import sqlite3
from Registry import Registry
from sqlalchemy import Column, Integer, Float, String, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from gooey import Gooey, GooeyParser

Base = declarative_base()
logging.basicConfig()
logging.getLogger('sqlalchemy.engine').setLevel(logging.ERROR)

# Registry values for common malware locations
class manualCheck(Base):
    __tablename__ = 'Review'

    id = Column(Integer, primary_key = True)
    HiveName = Column(String)
    Path = Column(String)
    Location = Column(String)
    Name = Column(String)
    Value = Column(String)

    def __init__(self, HiveName, Path, Location, Name, Value, **kwargs):
        self.HiveName = HiveName
        self.Path = Path
        self.Location = Location
        self.Name = Name
        self.Value = Value

# Registry values for files related to executable extensions
class simpleScan(Base):
    __tablename__ = 'Scan'

    id = Column(Integer, primary_key = True)
    HiveName = Column(String)
    Path = Column(String)
    Keyword = Column(String)
    Name = Column(String)
    Value = Column(String)
    Timestamp = Column(String)

    def __init__(self, HiveName, Path, Keyword, Name, Value, Timestamp, **kwargs):
        self.HiveName = HiveName
        self.Path = Path
        self.Keyword = Keyword
        self.Name = Name
        self.Value = Value
        self.Timestamp = Timestamp

# If the scan is for the current machine, use VirusTotal report 
class reportInfo(Base):
    __tablename__ = 'vtReport'

    id = Column(Integer, primary_key = True)
    HiveName = Column(String)
    Path = Column(String)
    Name = Column(String)
    Value = Column(String)
    PermaLink = Column(String)
    Positives = Column(Integer)

    def __init__(self, HiveName, Path, Name, Value, PermaLink, Positives, **kwargs):
        self.HiveName = HiveName
        self.Path = Path
        self.Name = Name
        self.Value = Value
        self.PermaLink = PermaLink
        self.Positives = Positives

# If report does not exist on VirusTotal, create a new scan
class scanInfo(Base):
    __tablename__ = 'vtScan'

    id = Column(Integer, primary_key = True)
    HiveName = Column(String)
    Path = Column(String)
    Name = Column(String)
    Value = Column(String)
    PermaLink = Column(String)

    def __init__(self, HiveName, Path, Name, Value, PermaLink, **kwargs):
        self.HiveName = HiveName
        self.Path = Path
        self.Name = Name
        self.Value = Value
        self.PermaLink = PermaLink

# Errors in reports
class errorInfo(Base):
    __tablename__ = 'vtError'

    id = Column(Integer, primary_key = True)
    HiveName = Column(String)
    Path = Column(String)
    Name = Column(String)
    Value = Column(String)
    Error = Column(String)

    def __init__(self, HiveName, Path, Name, Value, Error, **kwargs):
        self.HiveName = HiveName
        self.Path = Path
        self.Name = Name
        self.Value = Value
        self.Error = Error


val = 1
class regAnalysis(object):
    def __init__(self, hive):
        try:
            self.hname = hive
            self.reg = Registry.Registry(hive)
        except:
            raise Exception('Invalid hive file')

        # test to see if hive file is for HKLM
        try:
            self.reg.open("Classes")
            self.lm = True
        except:
            self.lm = False

        self.found = []

        # Create or open database, create session to work on DB
        global val
        name = 'rr' + str(datetime.date.today()) + '_'
        while (True):
            if not os.path.isfile(name + str(val) + '.db'):
                break
            val = val + 1
        
        self.db = name + str(val) + '.db'
        self.engine = create_engine('sqlite:///' + self.db, echo = False)
        Base.metadata.create_all(self.engine)

        Session = sessionmaker(bind = self.engine)
        self.session = Session()


    """
        Save values and keys for shell folders
    """
    def shellEntry(self):
        print "Reading registry value for shell folders..."
        startUpShell = "Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders"
        userStartUpShell = "Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"

        # Check shell folder
        try:
            shell = self.reg.open(startUpShell)
            for value in shell.values():
                info = self.fillCheckTable(startUpShell, 'Shell Folders', value.name(), value.value())
                self.saveSQL(manualCheck(**info))
        except:
            print "Unable to read any or all \"Shell Folders\" values."
        
        # Check user shell folder
        try:
            userShell = self.reg.open(userStartUpShell)
            for value in userShell.values():
                info = self.fillCheckTable(userStartUpShell, 'User Shell Folders', value.name(), value.value())
                self.saveSQL(manualCheck(**info))
        except:
            print "Unable to read any or all \"User Shell Folders\" values."

        print "Done. Review \'Review\' table in " + self.db + " for suspicious entries.\n"


    """
        Save values for programs that will run after the user logs in.
    """
    def runEntry(self):
        print "Reading registry Run keys for programs that start on log in..."
        runPath = "Microsoft\\Windows\\CurrentVersion\\Run"
        runOncePath = "Microsoft\\Windows\\CurrentVersion\\RunOnce"

        try:
            run = self.reg.open(runPath)
            for value in run.values():
                info = self.fillCheckTable(runPath, 'Run', value.name(), value.value())
                self.saveSQL(manualCheck(**info))
        except:
            print "Unable to read any or all \"Run\" values."

        try:
            runOnce = self.reg.open(runOncePath)
            for value in runOnce.values():
                info = self.fillCheckTable(runOncePath, 'RunOnce', value.name(), value.value())
                self.saveSQL(manualCheck(**info))
        except:
            print "Unable to read any or all \"RunOnce\" values."

        print "Done. Review \'Review\' table in " + self.db + " for suspicious entries.\n"


    def localMachine(self):
        if self.lm == False:
            return
        
        self.spawnEntry()
        self.winlogonCheck()


    """
        Save values for exectuables that can open another program for certain extensions.
    """
    def spawnEntry(self):
        print "Reading potential spawn programs..."
        spawn = "Classes\\"
        shells = "\\Shell\\Open\\Command"
        spCheck = ['batfile', 'comfile', 'exefile', 'htafile', 'piffile']
        
         # Check each path combination above
        try:
            for p in spCheck:
                s = spawn + p + shells
                key = self.reg.open(s)

                for value in key.values():
                    if value.value() != "\"%1\" %*":
                        info = self.fillCheckTable(s, p, value.name(), value.value())
                        self.saveSQL(manualCheck(**info))
        except Exception as e:
            print e

        print "Done. Review \'Review\' table in " + self.db + " for possible issues.\n"


    def winlogonCheck(self):
        print "Checking Shell and Userinit used on log in..."
        wlo = "Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
        key = self.reg.open(wlo)
        
        for value in key.values():
            if 'Shell' == value.name() or 'shell' == value.name():
                if value.value() != 'explorer.exe':
                    info = self.fillCheckTable(wlo, 'Winlogon', value.name(), value.value())
                    self.saveSQL(manualCheck(**info))

            if 'Userinit' == value.name() or 'userinit' == value.name():
                if value.value().count('.exe') > 1 or 'userinit.exe' not in value.value():
                    info = self.fillCheckTable(wlo, 'Winlogon', value.name(), value.value())
                    self.saveSQL(manualCheck(**info))
        
        print "Done. Review \'Review\' table in " + self.db + " for possible issues.\n"


    def fillCheckTable(self, path, location, name, value):
        info = {}
        info['HiveName'] = self.hname
        info['Path'] = path
        info['Location'] = location
        info['Name'] = name
        info['Value'] = value
        return info


    """
        Perform scan for basic executables or code that could potentially be malware
    """
    def basicScan(self):
        search = ['.exe', '.bat', '.pif', '.vbx', '.vbs', '.ws', '.wsf', '.com', 'start', '.dll', '.drv', 'delete']
        self.v = []
        self.regValues = []
        self.regTerm = []
        try:
            print "Scanning for executables or similar objects..."
            self.simpleScanning(self.reg.root(), search)
            print "Finished scan. Check \'Scan\' table in " + self.db + " for possible issues.\n"
        except Exception as e:
            print 'Scanning failed. %s\n' % e
    
    """
        Focus on files that have paths on the disk. DFS on Registry
    """
    def simpleScanning(self, key, search):
        for value in key.values():
            if value.value_type() == Registry.RegSZ or value.value_type() == Registry.RegExpandSZ:
                for term in search:
                    if (term in value.value() or term in value.name()) and value.value() not in self.v:
                        info = self.fillScanTable(key.path(), term, value.name(), value.value(), key.timestamp())
                        self.saveSQL(simpleScan(**info))
                        self.v.append(value.value())
                        self.regValues.append(value)
                        self.regTerm.append(term)

        # follow the subkeys until the end
        for subkey in key.subkeys():
            try:
                self.simpleScanning(subkey, search)
            except:
                pass
    

    def fillScanTable(self, path, keyword, name, value, timestamp):
        info = {}
        info['HiveName'] = self.hname
        info['Path'] = path
        info['Keyword'] = keyword
        info['Name'] = name
        info['Value'] = value
        info['Timestamp'] = timestamp
        return info


    """
        For every value in the previous scan, get the absolute path and attempt to
        do a VirusTotal report.
    """
    def origin(self):
        import _winreg
        for i in range(len(self.regValues)):
            if self.regTerm[i] == 'start' or self.regTerm[i] == 'delete':
                continue
            
            value = self.regValues[i]
            term = self.regTerm[i]
            try:
                # Absolute path exists, but must be extracted
                if value.value_type() == Registry.RegSZ:
                    # Drive letter
                    start = value.value().index(':') - 1
                    if 'A' > value.value()[start] or 'Z' < value.value()[start]:
                        continue
                    
                    # end of substring for extension
                    end = value.value().index(term) + 4
                    if start > end:
                        continue

                    path = value.value()[start:end]
                    self.virusTotalReport(path, value.name(), value.value())

                # Relative path
                if value.value_type() == Registry.RegExpandSZ:
                    start = value.value().index('%')
                    end = value.value().index(term) + 4

                    # Get absolute path and get report
                    expanded = unicode(value.value()[start:end])
                    path = str(_winreg.ExpandEnvironmentStrings(expanded))
                    self.virusTotalReport(path, value.name(), value.value())
            except:
                pass


    """
        Connect to VirusTotal API to get report if the file has been evaluted before.
    """
    def virusTotalReport(self, path, vname, vvalue):
        vtReport = 'https://www.virustotal.com/vtapi/v2/file/report'
        BUF_SIZE = 65536
        sha256 = hashlib.sha256()

        # calculate sha256 hash for file
        try:
            file = open(path, 'rb')
            while True:
                data = file.read(BUF_SIZE)
                if not data:
                    break
                sha256.update(data)
        except:
            info = self.fillError(path, vname, vvalue, "Cannot open file.")
            self.saveSQL(errorInfo(**info))
            return
        
        params = {'apikey': '5de9f584625cdea3ef924b32bce91063bea27950f40f03e94a6b1fe4eacae0b5', 'resource': sha256.hexdigest()}

        try:
            # attempt to retrieve the report from VirusTotal API
            response = requests.get(vtReport, params=params, timeout=3)
            if response.json()['response_code'] == 1:
                # report exists, no errors
                info = self.fillVTReportTable(path, vname, vvalue, response.json()['permalink'], response.json()['positives'])
                self.saveSQL(reportInfo(**info))
            else:
                # request a new evaluation
                self.virusTotalScan(path, vname, vvalue)
        except:
            return self.virusTotalScan(path, vname, vvalue)


    def fillVTReportTable(self, path, name, value, link, positives):
        info = {}
        info['HiveName'] = self.hname
        info['Path'] = path
        info['Name'] = name
        info['Value'] = value
        info['PermaLink'] = link
        info['Positives'] = positives
        return info


    """
        Submit request for file analysis on VirusTotal.
    """
    def virusTotalScan(self, path, vname, vvalue):
        vtScan = 'https://www.virustotal.com/vtapi/v2/file/scan'
        params = {'apikey': '5de9f584625cdea3ef924b32bce91063bea27950f40f03e94a6b1fe4eacae0b5'}
        fileSize = os.path.getsize(path) / (1024.0 * 1024.0)

        # File size has to be less than 32 MB due to current privileges to use VirusTotal API
        if fileSize > 32.0:
            info = self.fillError(path, vname, vvalue, "File size greater than 32MB. Try analysis by visiting VirusTotal and dropping the file there.")
            self.saveSQL(errorInfo(**info))
            return

        # open file
        try:
            file = open(path, 'rb')
        except:
            info = self.fillError(path, vname, vvalue, "Cannot open file.")
            self.saveSQL(errorInfo(**info))
            return

        files = {'file': file}
        try:
            # submit request for analysis
            response = requests.post(vtScan, files=files, params=params, verify=False, timeout=3)
            if response.json()['response_code'] == 1:
                info = self.fillVTScanTable(path, vname, vvalue, response.json()['permalink'])
                self.saveSQL(scanInfo(**info))
        except Exception as e:
            info = self.fillError(path, vname, vvalue, str(e))
            self.saveSQL(errorInfo(**info))


    def fillError(self, path, name, value, error):
        info = {}
        info['HiveName'] = self.hname
        info['Path'] = path
        info['Name'] = name
        info['Value'] = value
        info['Error'] = error
        return info


    def fillVTScanTable(self, path, name, value, link):
        info = {}
        info['HiveName'] = self.hname
        info['Path'] = path
        info['Name'] = name
        info['Value'] = value
        info['PermaLink'] = link
        return info


    def saveSQL(self, row):
        self.session.add(row)
        self.session.commit()


"""
    Summary of what was found in registry
"""
def summaryReport(info, scan):
    global val
    name = "summary" + str(val) + '.txt'
    summary = open(name, 'w')
    db = sqlite3.connect(info.db)
    cur = db.cursor()

    checkCount = cur.execute("SELECT COUNT(*) FROM Review").fetchall()
    totalCount = cur.execute("SELECT COUNT(*) FROM Scan").fetchall()
    if scan:
        vtReportCount = cur.execute("SELECT COUNT(*) FROM vtReport").fetchall()
        vtReportPosi = cur.execute("SELECT COUNT(*) FROM vtReport WHERE Positives >= 1").fetchall()
        vtScanCount = cur.execute("SELECT COUNT(*) FROM vtScan").fetchall()
        vtErrorCount = cur.execute("SELECT COUNT(*) FROM vtError").fetchall()
    else:
        cur.execute("DROP TABLE vtReport")
        cur.execute("DROP TABLE vtScan")
        cur.execute("DROP TABLE vtError")

    summary.write("Hive: %s\nDate: %s\nDatabase Name: %s\n\n" % (info.hname, datetime.date.today(), info.db))
    summary.write("Table Name: Review\nFound %s items to be examined.\n\n" % (checkCount[0][0]))
    summary.write("Table Name: Scan\nFound %s executables and files that are in the registry.\n\n" % totalCount[0][0])

    if scan:
        summary.write("Table Name: vtReport\nFound %s reports from VirusTotal. "  % vtReportCount[0][0] +
            "There are %s positive hits for malware.\n\n" % vtReportPosi[0][0])
        summary.write("Table Name: vtScan\nFound %s scans sent to VirusTotal to be reviewed later.\n\n" % vtScanCount[0][0])
        summary.write("Table Name: vtError\nThere were %s registry values that were unable to be processed on VirusTotal.\n\n" % vtErrorCount[0][0])

        if vtReportPosi[0][0] > 0:
            summary.write("Potential Malware definitely found.")
    else:
        summary.write("Cannot conclude malware exists. Review database for suspicious values.")

    print "Check " + name


@Gooey
def main():
    parser = GooeyParser(description = 'Registry Scanner for Malware Detection')
    parser.add_argument('hivePath', help="Path to Windows registry hive file", widget='FileChooser')
    parser.add_argument('-scan', action='store_true', help="Hive file is for current machine. Allows "
                                            + "connection to VirusTotal for file analysis.")

    args = parser.parse_args()

    # Perform registry analysis
    curr = regAnalysis(args.hivePath)
    curr.shellEntry()
    curr.runEntry()
    curr.localMachine()
    curr.basicScan()

    if args.scan == True:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        curr.origin()
    
    summaryReport(curr, args.scan)

if __name__ == '__main__':
    main()
