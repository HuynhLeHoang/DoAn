from os import sched_getparam
import os
import TableFromFile
import graphviz


class Graphic:
    def __init__(self, filename):
        self.filename = filename
        self.table = TableFromFile.TableFromFile(filename, True)
    
    def render(self, output, sensor):
        sip = self.table.getColumn('sIP')
        sport = self.table.getColumn('sPort')
        dip = self.table.getColumn('dIP')
        dport = self.table.getColumn('dPort')
        source = list()
        destination = list()
        for i in range(0, len(sip)):
            if(('ip=' + sip[i].strip() + '-port=' + str(sport[i])) not in source):
                source.append('ip=' + sip[i].strip() + '-port=' + str(sport[i]))
            if(('ip=' + dip[i].strip() + '-port=' + str(dport[i])) not in destination):
                destination.append('ip=' + dip[i].strip() + '-port=' + str(dport[i]))
        
        g = graphviz.Graph(filename = output + '.gv', format= 'png', encoding='utf-8')
        
        for i in range(0, len(source)):
            g.node(source[i],source[i])
        g.node(sensor, sensor, shape='invhouse',style='filled',color='green2')
        for i in range(0, len(destination)):
            g.node(destination[i],destination[i], shape='box', style='filled',color='deepskyblue')
            
        for i in range(0, len(source)):
            g.edge(str(source[i]), sensor)
            
        for i in range(0, len(destination)):
            g.edge(sensor,str(destination[i]))
        os.chdir('static')
        os.chdir('img')
        g.save()        
        g.render(filename=output +  '.gv', view=0, cleanup=1)
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