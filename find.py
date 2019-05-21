'''
    find.py
    Author: Nathan Ly

    Find registry key or values that match a given set of terms and/or fall 
    within a certain range of time.
'''
import requests
import os
import hashlib
import sys
import argparse
import datetime
import logging
from Registry import Registry
from gooey import Gooey, GooeyParser
from sqlalchemy import Column, Integer, Float, String, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine

Base = declarative_base()
logging.basicConfig()
logging.getLogger('sqlalchemy.engine').setLevel(logging.ERROR)

# Save findings of search
class results(Base):
    __tablename__ = 'Results'

    id = Column(Integer, primary_key = True)
    HiveName = Column(String)
    Path = Column(String)
    Keyword = Column(String)
    Timestamp = Column(String)
    Name = Column(String)
    Value = Column(String)

    def __init__(self, HiveName, Path, Keyword, Timestamp, Name, Value, **kwargs):
        self.HiveName = HiveName
        self.Path = Path
        self.Keyword = Keyword
        self.Timestamp = Timestamp
        self.Name = Name
        self.Value = Value


class find(object):
    def __init__(self, hive, start, end, search):
        try:
            self.hname = hive
            self.reg = Registry.Registry(hive)
            self.start = start
            self.end = end
            self.search = search
        except:
            raise Exception('Invalid hive file')

        # Set DB name
        val = 1
        name = 'f' + str(datetime.date.today()) + '_'
        while (True):
            if not os.path.isfile(name + str(val) + '.db'):
                break
            val = val + 1
        
        self.dbName = name + str(val) + '.db'
        self.db = name + str(val) + '.db'
        self.engine = create_engine('sqlite:///' + self.db, echo = False)
        Base.metadata.create_all(self.engine)

        Session = sessionmaker(bind = self.engine)
        self.session = Session()


    def beginSearch(self):
        self.searchTerms(self.reg.root())
        print "Check " + self.dbName


    """
        Perform search based on parameters.
    """
    def searchTerms(self, key):
        if self.start <= key.timestamp() <= self.end:
            for value in key.values():
                if value.value_type() == Registry.RegSZ or value.value_type() == Registry.RegMultiSZ:
                    if self.search == []:
                        # No search terms provided
                        info = self.fillInfo(key.path(), ' ', str(key.timestamp()), value.name(), value.value())
                        self.saveSQL(results(**info))
                    else:
                        for term in self.search:
                            # check if term is in substring
                            if term in value.name() or term in value.value() or term in key.path():
                                info = self.fillInfo(key.path(), term, str(key.timestamp()), value.name(), value.value())
                                self.saveSQL(results(**info))
        
        for subkey in key.subkeys():
            try:
                self.searchTerms(subkey)
            except: 
                pass


    def fillInfo(self, path, keyword, timestamp, name, value):
        info = {}
        info['HiveName'] = self.hname
        info['Path'] = path
        info['Keyword'] = keyword
        info['Timestamp'] = timestamp
        info['Name'] = name
        info['Value'] = value
        return info


    def saveSQL(self, row):
        self.session.add(row)
        self.session.commit()

@Gooey
def main():
    parser = GooeyParser(description = 'Registry Search for Timestamp (inclusive dates) or Keywords')
    parser.add_argument('hive', help="Windows registry hive file", widget='FileChooser')
    parser.add_argument('-start', action='store', dest='startDate', help="Start date YYYY-MM-DD",
                            widget='DateChooser')
    parser.add_argument('-end', action='store', dest='endDate', help="End date YYYY-MM-DD", widget='DateChooser')
    parser.add_argument('-search', nargs='*', default=[], help="Search terms to find in registry (space delimited).")

    args = parser.parse_args()

    # check if a search parameter was provided
    if not args.search and not args.startDate and not args.endDate:
        print "Must include a search time, start date, or end date.\n"
        return


    # process start date if provided
    if args.startDate != None:
        try:
            args.startDate = datetime.datetime(int(args.startDate[:4]), int(args.startDate[5:7]), int(args.startDate[-2:]), 0, 0, 0)
        except:
            print 'Unable to process: ' + args.startDate + '\n'
            return
    else:
        args.startDate = datetime.datetime(1970, 1, 1)


    # process end date if provided
    if args.endDate != None:
        try:
            args.endDate = datetime.datetime(int(args.endDate[:4]), int(args.endDate[5:7]), int(args.endDate[-2:]), 23, 59, 59)
        except:
            print 'Unable to process: ' + args.startDate + '\n'
            return
    else:
        now = datetime.datetime.now()
        args.endDate = datetime.datetime(now.year, now.month, now.day + 1, 23, 59, 59)


    # check if order of dates are correct
    if args.startDate > args.endDate:
        print 'Start date is after end date: %s - %s\n' % (args.startDate.strftime("%x"), args.endDate.strftime("%x"))
        return


    # begin search
    curr = find(args.hive, args.startDate, args.endDate, args.search)
    curr.beginSearch()

if __name__ == '__main__':
    main()