from itertools import count
import os
import pyshark
import subprocess
from datetime import datetime

class PCAPHandle:
    '''handle PCAP file that is uploaded. Extract and match MAC with IP Address'''
    def __init__(self, filepath):
        self.filepath = filepath
        try:
            
            self.cap = pyshark.FileCapture(os.getcwd() + '/uploads/' + filepath)
            
        except:
            pass

    def match(self):
        result = dict()
        for pkt in self.cap:
            try:
                smac = pkt.eth.src
                sip = pkt.ip.src
                dmac = pkt.eth.dst
                dip = pkt.ip.dst
                if sip not in result:
                    result[sip] = list()
                if dip not in result:
                    result[dip] = list()
                if smac not in result[sip]:
                    result[sip].append(smac)
                if dmac not in result[dip]:
                    result[dip].append(dmac)
            except:
                pass
        
        return result

    def count(self):
        counter = 0
        for pkg in self.cap:
            counter += 1
        return counter

    def getdate(self):
        
        os.chdir('uploads')
        command = 'capinfos -a -e {file}'.format(file=self.filepath)
        value = subprocess.getoutput(command)
        _startdate = value.split()[6].replace('-','/') + 'T' + value.split()[7][:8]
        _enddate = value.split()[-2].replace('-','/') + 'T' + value.split()[-1][:8]
        os.chdir('..')

        return _startdate,_enddate


if __name__=='__main__':
    pcap = PCAPHandle('FullPack.pcap')
    print(pcap.getdate())
