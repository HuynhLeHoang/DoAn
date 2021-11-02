from datetime import datetime
import os
import pyshark
import TableFromCommand

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
            break
        return counter

    def getdate(self):
        
        startdatecmd = 'rwsort traffic.rw --fields=stime --output-path=stdout | rwcut --no-columns| head -2 > getstart.txt'
        enddatecmd = 'rwsort traffic.rw --fields=etime --reverse --output-path=stdout | rwcut --no-columns| head -2 > getend.txt'
        start = TableFromCommand.TableFromCommand(startdatecmd, 'getstart.txt')
        start = start.execute()
        end = TableFromCommand.TableFromCommand(enddatecmd, 'getend.txt')
        end = end.execute()
        start = str(start.getColumn('sTime')[0]).split('.')[0]
        start = datetime.strptime(start,'%Y/%m/%dT%H:%M:%S').strftime('%Y/%m/%dT%H:%M:%S')
        end = str(end.getColumn('eTime')[0]).split('.')[0]
        end = datetime.strptime(end,'%Y/%m/%dT%H:%M:%S').strftime('%Y/%m/%dT%H:%M:%S')

        return start,end


if __name__=='__main__':
    pcap = PCAPHandle('FullPack.pcap')
    print(pcap.getdate())
