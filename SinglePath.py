import os
import TableFromCommand

class SinglePath:
    '''single path analysis object'''
    def __init__(self, filename, counts):
        self.filename = filename
        self.counts = counts

    def lowbyte(self):
        command = 'rwfilter {filename} --bytes=0-300 --pass=stdout | rwuniq --bin-time=3600 --fields=stime,type --values=records --sort-output>low-byte.txt'.format(filename=self.filename)
        table = TableFromCommand.TableFromCommand(command, 'low-byte.txt')
        table = table.execute()
        return table
    
    def medbyte(self):
        command = 'rwfilter {filename} --bytes=301-100000 --pass=stdout | rwuniq --bin-time=3600 --fields=stime,type --values=records --sort-output>med-byte.txt'.format(filename=self.filename)
        table = TableFromCommand.TableFromCommand(command, 'med-byte.txt')
        table = table.execute()
        return table

    def highbyte(self):
        command = 'rwfilter {filename} --bytes=100001- --pass=stdout | rwuniq --bin-time=3600 --fields=stime,type --values=records --sort-output>high-byte.txt'.format(filename=self.filename)
        table = TableFromCommand.TableFromCommand(command, 'high-byte.txt')
        table = table.execute()
        return table

    def shortduration(self):
        command = 'rwfilter {filename} --duration=0-60 --pass=stdout | rwuniq --bin-time=3600 --fields=stime,type --values=records --sort-output>short-duration.txt'.format(filename=self.filename)
        table = TableFromCommand.TableFromCommand(command, 'short-duration.txt')
        table = table.execute()
        return table

    def medduration(self):
        command = 'rwfilter {filename} --duration=0-60 --pass=stdout | rwuniq --bin-time=3600 --fields=stime,type --values=records --sort-output>med-duration.txt'.format(filename=self.filename)
        table = TableFromCommand.TableFromCommand(command, 'med-duration.txt')
        table = table.execute()
        return table

    def longduration(self):
        command = 'rwfilter {filename} --duration=0-60 --pass=stdout | rwuniq --bin-time=3600 --fields=stime,type --values=records --sort-output>long-duration.txt'.format(filename=self.filename)
        table = TableFromCommand.TableFromCommand(command, 'long-duration.txt')
        table = table.execute()
        return table

    def overallview(self):
        result = dict()
        command = 'rwcut --fields=1-4,protocol,bytes,duration --num-recs={counts} traffic.rw > overrallview.txt'.format(counts = self.counts)
        overalltable = TableFromCommand.TableFromCommand(command, 'overallview.txt')
        overalltable = overalltable.execute()
        result['overall'] = overalltable
        datatype = ['protocol', 'sip', 'dip', 'sport', 'dport']
        for x in datatype:
            command = 'rwstats --fields={datatype} --count={count} {filename} > {datatype}.txt'.format(filename = self.filename, datatype = x, count = self.counts)
            temptable = TableFromCommand.TableFromCommand(command, x + '.txt')
            temptable = temptable.execute()
            result[x] = temptable
        return result
    
