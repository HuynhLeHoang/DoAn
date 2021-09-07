from flask import Flask, redirect, url_for, render_template, request
import TableFromFile
import TableFromCommand
import os
import ChartRender
import asyncio
from datetime import datetime
import SinglePath

protocols = ['ICMP','IGMP','GGP','IP-in-IP','ST','TCP','CBT','EGP','IGP','BBN-RCC-MON','NVP-II','PUP','ARGUS','EMCON','XNET','CHAOS','UDP','MUX','DCN-MEAS','HMP','PRM','XNS-IDP','TRUNK-1','TRUNK-2','LEAF-1','LEAF-2','RDP','IRTP','ISO-TP4','NETBLT','MFE-NSP','MERIT-INP','DCCP','3PC','IDPR','XTP','DDP','IDPR-CMTP','TP++','IL','IPv6','SDRP','IPv6-Route','IPv6-Frag','IDRP','RSVP','GRE','DSR','BNA','ESP','AH','I-NLSP','SwIPe','NARP','MOBILE','TLSP','SKIP','IPv6-ICMP','IPv6-NoNxt','IPv6-Opts','','CFTP','','SAT-EXPAK','KRYPTOLAN','RVD','IPPC','','SAT-MON','VISA','IPCU','CPNX','CPHB','WSN','PVP','BR-SAT-MON','SUN-ND','WB-MON','WB-EXPAK','ISO-IP','VMTP','SECURE-VMTP','VINES','TTP','IPTM','NSFNET-IGP','DGP','TCF','EIGRP','OSPF','Sprite-RPC','LARP','MTP','AX.25','OS','MICP','SCC-SP','ETHERIP','ENCAP','','GMTP','IFMP','PNNI','PIM','ARIS','SCPS','QNX','A/N','IPComp','SNP','Compaq-Peer','IPX-in-IP','VRRP','PGM','','L2TP','DDX','IATP','STP','SRP','UTI','SMP','SM','PTP','IS-IS over IPv4','FIRE','CRTP','CRUDP','SSCOPMCE','IPLT','SPS','PIPE','SCTP','FC','RSVP-E2E-IGNORE','Mobility Header','UDPLite','MPLS-in-IP','manet','HIP','Shim6','WESP','ROHC','Ethernet']
TEMPLATE_DIR = os.path.abspath('templates')
STATIC_DIR = os.path.abspath('static')

date=TableFromCommand.TableFromCommand('rwsiteinfo --fields=repo-start-date,repo-end-date >> repo-date.txt','repo-date.txt')
date=date.execute()
startdate=date.getColumn('Start-Date')[0]
enddate=date.getColumn('End-Date')[0]

app = Flask(__name__, static_folder="static")

@app.route('/', methods = ['GET','POST'])
def index():
    global startdate
    global enddate
    global protocols
    #handle request
    _startdate = startdate
    _enddate = enddate
    _counts = 10
    if 'startdate' in request.form:
        _startdate = datetime.strptime(request.form['startdate'] + ':00','%Y-%m-%dT%H:%M:%S').strftime('%Y/%m/%dT%H:%M:%S')
    if 'enddate' in request.form:
        _enddate = datetime.strptime(request.form['enddate'] + ':00','%Y-%m-%dT%H:%M:%S').strftime('%Y/%m/%dT%H:%M:%S')
    if 'counts' in request.form:
        _counts = int(request.form['counts'])
    #calculate top flow record
    topFlowByRecordCommand='''rwfilter --start={_startdate} --end={_enddate} --type=in,inweb,out,outweb --proto=0- --pass=stdout|rwstats --count {_counts} --fields sip,dip --values=records --no-columns >> topFlowByRecord.txt'''
    topFlowBySizeCommand = '''rwfilter --type all --proto=0- --start={_startdate} --end={_enddate} --pass=stdout | rwstats --count {_counts} --fields sip,dip,bytes  --values=bytes --top --no-columns >> topFlowBySize.txt'''
    topFlowByRecordCommand = topFlowByRecordCommand.format(_startdate=_startdate, _enddate=_enddate, _counts=_counts)
    topFlowBySizeCommand = topFlowBySizeCommand.format(_startdate=_startdate, _enddate=_enddate, _counts=_counts)

    topFlowRecordTable = TableFromCommand.TableFromCommand(topFlowBySizeCommand, 'topFlowBySize.txt')
    topFlowRecordTable = topFlowRecordTable.execute()
    topFlowByRecordsTable = TableFromCommand.TableFromCommand(topFlowByRecordCommand,'topFlowByRecord.txt')
    topFlowByRecordsTable = topFlowByRecordsTable.execute()

    dataset = ChartRender.dataSet('"rgba(238, 139, 152, 0.7)"',topFlowRecordTable.getColumn('Bytes'),'"Top Flow Record by size"')
    datasets = [dataset]
    barchart = ChartRender.barChart()
    topFlowRecordChartlabels = list()
    topFlowRecordRow = topFlowRecordTable.getAllRow()
    for x in topFlowRecordRow:
        topFlowRecordChartlabels.append(str(x[0]).strip() + ':' + str(x[1]).strip() + '->' + str(x[2]).strip() + ':' + str(x[3]).strip())
    chart = barchart.barChartRender(topFlowRecordChartlabels, datasets, 'topFlowRecordChart', 'true')
    dataset = ChartRender.dataSet('"rgba(134, 77, 217, 0.57)"',topFlowRecordTable.getColumn('%Bytes'),'"Top Flow Record Percentage"')
    datasets = [dataset]
    percentagechart = barchart.barChartRender(topFlowRecordChartlabels, datasets, 'topFlowRecordPercentage', 'false')
    dataset = ChartRender.dataSet('"rgba(75, 75, 75, 0.7)"',topFlowRecordTable.getColumn('bytes'),'"Most package"')
    datasets = [dataset]
    lastbytechart = barchart.barChartRender(topFlowRecordChartlabels, datasets, 'topFlowRecordLastByte', 'false')
    #top flow by number of record
 
    dataset = ChartRender.dataSet('"rgba(238, 139, 152, 0.7)"',topFlowByRecordsTable.getColumn('Records'),'"Top Flow Record by size"')
    datasets = [dataset]
    barchart = ChartRender.barChart()
    topFlowRecordChartlabels = list()
    topFlowRecordRow = topFlowByRecordsTable.getAllRow()
    for x in topFlowRecordRow:
        topFlowRecordChartlabels.append(str(x[0]).strip() + ':' + str(x[1]).strip() + '->' + str(x[2]).strip() + ':' + str(x[3]).strip())
    topFlowByRecordsBarChart = barchart.barChartRender(topFlowRecordChartlabels, datasets, 'topFlowByRecordBarChart', 'true')
    #pie chart 
    dataset = topFlowByRecordsTable.getColumn('%Records')
    if len(topFlowByRecordsTable.getColumn('cumul_%'))>0:
        dataset.append(100 - int(topFlowByRecordsTable.getColumn('cumul_%')[-1]))
    else:
        dataset.append(100)
    topFlowByRecordsPieChart = ChartRender.customPieChart()
    topFlowRecordChartlabels = list()
    topFlowRecordRow = topFlowByRecordsTable.getAllRow()
    for x in topFlowRecordRow:
        topFlowRecordChartlabels.append(str(x[0]).strip() +'->' + str(x[1]).strip())
    topFlowRecordChartlabels.append('Others')
    topFlowByRecordsPieChart = topFlowByRecordsPieChart.customPieChartRender('topFlowByRecordsPieChart',topFlowRecordChartlabels, dataset)

    return render_template('index.html',
    topFlowByRecordsPieChart = topFlowByRecordsPieChart,
    topFlowByRecordsTable = topFlowByRecordsTable,
    topFlowByRecordsBarChart = topFlowByRecordsBarChart, 
    topFlowRecordTable = topFlowRecordTable, 
    topFlowRecordChart = chart, 
    topFlowRecordPercentChart = percentagechart, 
    topFlowRecordLastByteChart = lastbytechart, 
    startdate=datetime.strptime(startdate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'), 
    enddate=datetime.strptime(enddate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'),
    _startdate=datetime.strptime(_startdate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'),
    _enddate=datetime.strptime(_enddate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'),
    counts=_counts)

@app.route('/port')
def port():
    #top coming flow with destination port
    topCDPTable = TableFromFile.TableFromFile('topDPortIn', True)
    topCDPChart = ChartRender.customPieChart()
    labels = topCDPTable.getColumn('dPort')
    labels.append('Others')
    data = topCDPTable.getColumn('%Records')
    data.append(100)
    currentIndex = 0
    for x in data:
        data[len(data)-1] = data[len(data)-1] - float(x)
        currentIndex += 1
        if currentIndex == len(data)-2:
            break
    topCDPChart = topCDPChart.customPieChartRender('topCDPChart',labels,data)

    #top coming flow with source port
    topCSPTable = TableFromFile.TableFromFile('topSPortIn', True)
    topCSPChart = ChartRender.customPieChart()
    labels = topCSPTable.getColumn('sPort')
    labels.append('Others')
    data = topCSPTable.getColumn('%Records')
    data.append(100)
    currentIndex = 0
    for x in data:
        data[len(data)-1] = data[len(data)-1] - float(x)
        currentIndex += 1
        if currentIndex == len(data)-2:
            break
    topCSPChart = topCSPChart.customPieChartRender('topCSPChart',labels,data)

    #top out going flow with destination port
    topODPTable = TableFromFile.TableFromFile('topDPortOut', True)
    topODPChart = ChartRender.customPieChart()
    labels = topODPTable.getColumn('dPort')
    labels.append('Others')
    data = topODPTable.getColumn('%Records')
    data.append(100)
    currentIndex = 0
    for x in data:
        data[len(data)-1] = data[len(data)-1] - float(x)
        currentIndex += 1
        if currentIndex == len(data)-2:
            break
    topODPChart = topODPChart.customPieChartRender('topODPChart',labels,data)

    #top out going flow with source port
    topOSPTable = TableFromFile.TableFromFile('topSPortOut', True)
    topOSPChart = ChartRender.customPieChart()
    labels = topOSPTable.getColumn('sPort')
    labels.append('Others')
    data = topOSPTable.getColumn('%Records')
    data.append(100)
    currentIndex = 0 
    for x in data:
        data[len(data)-1] = data[len(data)-1] - float(x)
        currentIndex += 1
        if currentIndex == len(data)-2:
            break
    topOSPChart = topOSPChart.customPieChartRender('topOSPChart',labels,data)    

    return render_template('port.html', topCDPTable = topCDPTable, topCDPChart = topCDPChart, topCSPTable = topCSPTable, topCSPChart = topCSPChart, topODPTable = topODPTable, topODPChart = topODPChart, topOSPTable = topOSPTable, topOSPChart = topOSPChart)

@app.route('/iptoip', methods = ['GET'])
def iptoip():
    global startdate
    global enddate
    global protocols
    _startdate = startdate
    _enddate = enddate
    if 'startdate' in request.args:
        _startdate = request.args.get('startdate')
    if 'enddate' in request.args:
        _startdate = request.args.get('enddate')
    sip = request.args.get('sip')
    dip = request.args.get('dip')
    command = '''rm iptoip.rw; rwfilter --proto=0- --start={startdate} --end={enddate} --type=in,inweb,out,outweb --pass=iptoip.rw --saddress={sip} --daddress={dip}; rwsort iptoip.rw --fields=bytes --reverse | rwcut --fields=sTime,eTime,sip,sport,dip,dport,bytes --num-recs=50 --no-columns >> iptoip.txt'''
    command = command.format(sip = sip, dip = dip, startdate = _startdate, enddate = _enddate)
    table = TableFromCommand.TableFromCommand(command, 'iptoip.txt')
    compareTable = table.execute()
    #by protocol
    command = '''rm iptoip.rw; rwfilter --proto=0- --start={startdate} --end={enddate} --type=in,inweb,out,outweb --pass=iptoip.rw --saddress={sip} --daddress={dip}; rwsort iptoip.rw --fields=bytes --reverse | rwstats --count 50 --fields sip,dip,proto --values=records --no-columns >> iptoip.txt'''
    command = command.format(sip = sip, dip = dip, startdate = _startdate, enddate = _enddate)
    table = TableFromCommand.TableFromCommand(command, 'iptoip.txt')
    compareTableByPro = table.execute()
    compareTableByPro.Table['protocol'] = compareTableByPro.Table['protocol'].astype(str)
    for index, row in compareTableByPro.Table.iterrows():
        compareTableByPro.Table.at[index, 'protocol'] = protocols[int(compareTableByPro.Table.at[index, 'protocol']) - 1]
    #by package
    command = '''rm iptoip.rw; rwfilter --proto=0- --start={startdate} --end={enddate} --type=in,inweb,out,outweb --pass=iptoip.rw --saddress={sip} --daddress={dip}; rwsort iptoip.rw --fields=bytes --reverse | rwstats --count 50 --fields sip,dip,sport,dport --values=records --no-columns >> iptoip.txt'''
    command = command.format(sip = sip, dip = dip, startdate = _startdate, enddate = _enddate)
    table = TableFromCommand.TableFromCommand(command, 'iptoip.txt')
    compareTableByPackage = table.execute()
    return render_template('iptoip.html', compareTable = compareTable, sip=sip,dip=dip, compareTableByPro=compareTableByPro,compareTableByPackage=compareTableByPackage)

@app.route('/singlepathsimple', methods=['GET'])
def singlepathSampleInit():
    global startdate
    global enddate
    global protocols
    #handle request
    _startdate = startdate
    _enddate = enddate
    _counts = 10
    return render_template('singlepathInit.html',
    startdate=datetime.strptime(startdate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'), 
    enddate=datetime.strptime(enddate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'))

@app.route('/singlepathsimple', methods=['POST'])
def singplepathSampleAnalysis():
    _startdate = datetime.strptime(request.form['startdate'] + ':00','%Y-%m-%dT%H:%M:%S').strftime('%Y/%m/%dT%H:%M:%S')
    _enddate = datetime.strptime(request.form['enddate'] + ':00','%Y-%m-%dT%H:%M:%S').strftime('%Y/%m/%dT%H:%M:%S')
    _counts = request.form['counts']
    _sensor = request.form['sensor']
    _id = request.form['ip']
    #init data
    command = 'rwfilter --start={start} --end={end} --sensor={sensor} --type=in,inweb,out,outweb --any-address={ip} --pass=traffic.rw'
    os.chdir('data')
    os.system(command)
    os.chdir('..')
    singlepath = SinglePath.SinglePath('traffic.rw', _counts)
    

    
if __name__ == '__main__':
    app.run(debug = True, host='0.0.0.0')
   
