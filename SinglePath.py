import os
import TableFromCommand

class SinglePath:
    '''single path analysis object'''
    def __init__(self, filename, counts):
        self.filename = filename
        self.counts = counts

    def lowbyte(self):
        command = 'rwfilter {filename} --bytes=0-300 --pass=stdout | rwuniq --bin-time=3600 --fields=stime,type --values=records --sort-output --no-columns>low-byte.txt'.format(filename=self.filename)
        table = TableFromCommand.TableFromCommand(command, 'low-byte.txt')
        return table.execute()
    
    def medbyte(self):
        command = 'rwfilter {filename} --bytes=301-100000 --pass=stdout | rwuniq --bin-time=3600 --fields=stime,type --values=records --sort-output --no-columns>med-byte.txt'.format(filename=self.filename)
        table = TableFromCommand.TableFromCommand(command, 'med-byte.txt')
        return table.execute()

    def highbyte(self):
        command = 'rwfilter {filename} --bytes=100001- --pass=stdout | rwuniq --bin-time=3600 --fields=stime,type --values=records --sort-output --no-columns>high-byte.txt'.format(filename=self.filename)
        table = TableFromCommand.TableFromCommand(command, 'high-byte.txt')
        return table.execute()

    def shortduration(self):
        command = 'rwfilter {filename} --duration=0-60 --pass=stdout | rwuniq --bin-time=3600 --fields=stime,type --values=records --sort-output --no-columns>short-duration.txt'.format(filename=self.filename)
        table = TableFromCommand.TableFromCommand(command, 'short-duration.txt')
        return table.execute()

    def medduration(self):
        command = 'rwfilter {filename} --duration=61-120 --pass=stdout | rwuniq --bin-time=3600 --fields=stime,type --values=records --sort-output --no-columns>med-duration.txt'.format(filename=self.filename)
        table = TableFromCommand.TableFromCommand(command, 'med-duration.txt')
        return table.execute()

    def longduration(self):
        command = 'rwfilter {filename} --duration=121- --pass=stdout | rwuniq --bin-time=3600 --fields=stime,type --values=records --sort-output --no-columns>long-duration.txt'.format(filename=self.filename)
        table = TableFromCommand.TableFromCommand(command, 'long-duration.txt')
        return table.execute()

    def overallview(self):
        result = list()
        command = 'rwcut --fields=1-4,protocol,bytes,duration --num-recs={counts} traffic.rw --no-columns > overallview.txt'.format(counts = self.counts)
        overalltable = TableFromCommand.TableFromCommand(command, 'overallview.txt')
        overalltable = overalltable.execute()
        result.append(overalltable)
        datatype = ['protocol', 'sip', 'dip', 'sport', 'dport']
        for x in datatype:
            command = 'rwstats --fields={datatype} --count={count} {filename} > {datatype}.txt'.format(filename = self.filename, datatype = x, count = self.counts)
            temptable = TableFromCommand.TableFromCommand(command, x + '.txt')
            temptable = temptable.execute()
            result.append(temptable)
        return result
    
