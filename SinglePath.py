import os
import TableFromCommand



class SinglePath:
    '''single path analysis object'''
    def __init__(self, filename, counts):
        self.filename = filename
        self.counts = counts
        self.protocolsname = ['ICMP','IGMP','GGP','IP-in-IP','ST','TCP','CBT','EGP','IGP','BBN-RCC-MON','NVP-II','PUP','ARGUS','EMCON','XNET','CHAOS','UDP','MUX','DCN-MEAS','HMP','PRM','XNS-IDP','TRUNK-1','TRUNK-2','LEAF-1','LEAF-2','RDP','IRTP','ISO-TP4','NETBLT','MFE-NSP','MERIT-INP','DCCP','3PC','IDPR','XTP','DDP','IDPR-CMTP','TP++','IL','IPv6','SDRP','IPv6-Route','IPv6-Frag','IDRP','RSVP','GRE','DSR','BNA','ESP','AH','I-NLSP','SwIPe','NARP','MOBILE','TLSP','SKIP','IPv6-ICMP','IPv6-NoNxt','IPv6-Opts','','CFTP','','SAT-EXPAK','KRYPTOLAN','RVD','IPPC','','SAT-MON','VISA','IPCU','CPNX','CPHB','WSN','PVP','BR-SAT-MON','SUN-ND','WB-MON','WB-EXPAK','ISO-IP','VMTP','SECURE-VMTP','VINES','TTP','IPTM','NSFNET-IGP','DGP','TCF','EIGRP','OSPF','Sprite-RPC','LARP','MTP','AX.25','OS','MICP','SCC-SP','ETHERIP','ENCAP','','GMTP','IFMP','PNNI','PIM','ARIS','SCPS','QNX','A/N','IPComp','SNP','Compaq-Peer','IPX-in-IP','VRRP','PGM','','L2TP','DDX','IATP','STP','SRP','UTI','SMP','SM','PTP','IS-IS over IPv4','FIRE','CRTP','CRUDP','SSCOPMCE','IPLT','SPS','PIPE','SCTP','FC','RSVP-E2E-IGNORE','Mobility Header','UDPLite','MPLS-in-IP','manet','HIP','Shim6','WESP','ROHC','Ethernet']

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
        command = 'rwcut --fields=1-4,protocol,bytes --num-recs={counts} traffic.rw --no-columns > overallview.txt'.format(counts=self.counts)
        overalltable = TableFromCommand.TableFromCommand(command, 'overallview.txt')
        overalltable = overalltable.execute()
        overalltable.Table['protocol'] = overalltable.Table['protocol'].astype(str)
        for index, row in overalltable.Table.iterrows():
            overalltable.Table.at[index, 'protocol'] = self.protocolsname[int(overalltable.Table.at[index, 'protocol']) - 1]
        result.append(overalltable)
        datatype = ['protocol', 'sip', 'dip', 'sport', 'dport']
        for x in datatype:
            command = 'rwstats --fields={datatype} --count={count} {filename} > {datatype}.txt'.format(filename = self.filename, datatype = x, count = self.counts)
            temptable = TableFromCommand.TableFromCommand(command, x + '.txt')
            temptable = temptable.execute()
            if x == 'protocol':
                temptable.Table['pro'] = temptable.Table['pro'].astype(str)
                for index, row in temptable.Table.iterrows():
                    temptable.Table.at[index, 'pro'] = self.protocolsname[int(temptable.Table.at[index, 'pro']) - 1]
            result.append(temptable)
        return result
    
    def binsize(self):
        command = 'rwcount --bin-size=600 {filename} > binsize.txt'.format(filename=self.filename)
        table = TableFromCommand.TableFromCommand(command, 'binsize.txt')
        return table.execute()
