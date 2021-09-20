from os import sched_getparam
import TableFromFile
import graphviz

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
        g.edge(str(source[i]), 'S1', arrowhead='vee')
        
    for i in range(0, len(destination)):
        g.edge('S1',str(destination[i]), arrowhead='vee')
    print(g.source)
    g.view()
    