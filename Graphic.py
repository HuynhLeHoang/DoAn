from enum import unique
from os import sched_getparam
import os

from pyshark.tshark.tshark_json import duplicate_object_hook
import TableFromFile
import graphviz



class Graphic:
    def __init__(self, sipfile, dipfile, sfile, dfile):
        self.sfile = sfile
        self.dfile = dfile
        self.stable = TableFromFile.TableFromFile(sfile, True)
        self.dtable = TableFromFile.TableFromFile(dfile, True)
        self.siptable = TableFromFile.TableFromFile(sipfile, True)
        self.diptable = TableFromFile.TableFromFile(dipfile, True)
    
    def render(self, output, sensor, dictionary, allowip, allowport):
        sip = [ip.strip() for ip in self.siptable.getColumn('sIP')]
        #sport = self.sporttable.getColumn('sPort')
        dip = [ip.strip() for ip in self.diptable.getColumn('dIP')]
        #dport = self.dporttable.getColumn('dPort')
        #make ip addresses unique
        sip = list(set(sip))
        dip = list(set(dip))
        #sport = list(set(sport))
        #dport = list(set(dport))
        sourcezone = self.stable.Table.values.tolist()
        destinationzone = self.dtable.Table.values.tolist()
        
        g = graphviz.Graph(filename = output + '.gv', format= 'png', encoding='utf-8')
        temp_sip = list()
        for ip in sip:
            temp_sip.append(ip)
        for ip in sip:
            if len(ip)>15:
                temp_sip.remove(ip)
                continue
            if ip not in allowip and len(allowip)!=0:
                temp_sip.remove(ip)
        sip = list()
        for ip in temp_sip:
            sip.append(ip)
        temp_dip = list()
        for ip in dip:
            temp_dip.append(ip)
        for ip in dip:
            if len(ip)>15:
                temp_dip.remove(ip)
                continue
            if ip not in allowip and len(allowip)!=0:
                temp_dip.remove(ip)       
        dip = list()
        for ip in temp_dip:
            dip.append(ip)
        for ip in sip:            
            ip = "sip=" + str(ip).strip()
            g.node(ip,ip,  shape="box",style="filled",color="aquamarine")                  

        g.node(sensor, sensor, shape="invhouse",style="filled",color="green2")

        for ip in dip:
            ip = "dip=" + str(ip).strip()
            g.node(ip,ip, shape="box", style="filled",color="aquamarine")                
        
        #connecting node     
        
        for row in sourcezone:
            if len(str(row[0]).strip()) > 15:
                continue
            if str(row[1]) not in allowport and len(allowport)!=0:
                continue
            if str(row[0]).strip() in sip:
                sport = "sport=" + str(row[1]).strip()
                g.node(sport,sport, shape="box", style="filled",color="beige") 
                g.edge("sip=" + str(row[0]).strip(), sport)
                g.edge(sport,sensor)

        for row in destinationzone:
            if len(str(row[0]).strip()) > 15:
                continue
            if str(row[1]) not in allowport and len(allowport)!=0:
                continue
            if str(row[0]).strip() in dip:
                dport = "dport=" + str(row[1]).strip()
                g.node(dport,dport, shape="invhouse",style="filled",color="beige")
                g.edge(dport, "dip=" + str(row[0]).strip())
                g.edge(sensor, dport)
        
        for key in dictionary:
            if len(key)>15:
                continue
            for ele in dictionary[key]:
                if key in sip:
                    g.node("smac=" + str(ele).replace(':','-'), "smac=" + str(ele).replace(':','-'), shape="diamond", style="filled",color="deepskyblue")
                    g.edge("smac=" + str(ele).replace(':','-'), "sip=" + str(key).strip())
                if key in dip:
                    g.node("dmac=" + str(ele).replace(':','-'), "dmac=" + str(ele).replace(':','-'), shape="diamond", style="filled",color="deepskyblue")
                    g.edge("dip=" + str(key).strip(), "dmac=" + str(ele).replace(':','-'))
        
        os.chdir('static')
        os.chdir('img')
        with open(output + '.txt', 'w') as f:
            print(g.source, file=f)
        try:
            os.remove(output + ".png")
        except:
            pass
        g.save()       
        g.render(filename=output, view=0, cleanup=1)
        os.chdir('..')
        os.chdir('..')
        
    
    def renderNoPort():
        pass

'''
if __name__=='__main__':
    table = TableFromFile.TableFromFile('test.txt', True)
    sip = table.getColumn('sIP')
    sport = table.getColumn('sPort')
    dip = table.getColumn('dIP')
    dport = table.getColumn('dPort')
    source = list()
    destination = list()
    for i in range(0, len(sip)):
        if(('ip=' + sip[i].strip() + '-port=' + str(sport[i])) not in source):
            source.append('ip=' + sip[i].strip() + '-port=' + str(sport[i]))
        if(('ip=' + dip[i].strip() + '-port=' + str(dport[i])) not in destination):
            destination.append('ip=' + dip[i].strip() + '-port=' + str(dport[i]))
    
    g = graphviz.Graph(filename='test.gv')
    
    for i in range(0, len(source)):
        g.node(source[i],source[i])
    g.node('S1', 'S1', shape='invhouse',style='filled',color='green2')
    for i in range(0, len(destination)):
        g.node(destination[i],destination[i], shape='box', style='filled',color='deepskyblue')
        
    

    for i in range(0, len(source)):
        g.edge(str(source[i]), 'S1')
        g.edge_attr.update(arrowhead='vee', arrowsize='2')
    for i in range(0, len(destination)):
        g.edge('S1',str(destination[i]))
        g.edge_attr.update(arrowhead='vee', arrowsize='2')
    print(g.source)
    g.view()
'''