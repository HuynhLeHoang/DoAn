from itertools import count
import os
import pyshark
import os
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
        pkg = self.cap[0]
        _startdate = float(pkg.sniff_timestamp)
        _startdate = datetime.utcfromtimestamp(_startdate).strftime('%Y/%m/%dT%H:%M:%S')
        
        for pkg in self.cap:
            continue
        _enddate = float(pkg.sniff_timestamp)
        _enddate = datetime.utcfromtimestamp(_enddate).strftime('%Y/%m/%dT%H:%M:%S')
        return _startdate,_enddate


'''
if __name__=='__main__':
    pcap = PCAPHandle('FullPack.pcap')
    print(pcap.match())
'''