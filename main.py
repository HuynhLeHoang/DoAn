
from graphviz.backend import render
from werkzeug.utils import secure_filename
from itertools import count
from flask import Flask, redirect, url_for, render_template, request, abort, send_file, jsonify
from flask.sessions import NullSession
from werkzeug.utils import secure_filename
from itertools import count
from flask import Flask, redirect, url_for, render_template, request, abort
import TableFromFile
import TableFromCommand
import os
import ChartRender
import asyncio
from datetime import datetime, timedelta
import SinglePath
import pandas as pd
import Graphic
import readPCAP
from datetime import datetime
import SinglePath
import pandas as pd

dictionary = dict()
sensor = 'Sensor'
protocols = ['ICMP','IGMP','GGP','IP-in-IP','ST','TCP','CBT','EGP','IGP','BBN-RCC-MON','NVP-II','PUP','ARGUS','EMCON','XNET','CHAOS','UDP','MUX','DCN-MEAS','HMP','PRM','XNS-IDP','TRUNK-1','TRUNK-2','LEAF-1','LEAF-2','RDP','IRTP','ISO-TP4','NETBLT','MFE-NSP','MERIT-INP','DCCP','3PC','IDPR','XTP','DDP','IDPR-CMTP','TP++','IL','IPv6','SDRP','IPv6-Route','IPv6-Frag','IDRP','RSVP','GRE','DSR','BNA','ESP','AH','I-NLSP','SwIPe','NARP','MOBILE','TLSP','SKIP','IPv6-ICMP','IPv6-NoNxt','IPv6-Opts','','CFTP','','SAT-EXPAK','KRYPTOLAN','RVD','IPPC','','SAT-MON','VISA','IPCU','CPNX','CPHB','WSN','PVP','BR-SAT-MON','SUN-ND','WB-MON','WB-EXPAK','ISO-IP','VMTP','SECURE-VMTP','VINES','TTP','IPTM','NSFNET-IGP','DGP','TCF','EIGRP','OSPF','Sprite-RPC','LARP','MTP','AX.25','OS','MICP','SCC-SP','ETHERIP','ENCAP','','GMTP','IFMP','PNNI','PIM','ARIS','SCPS','QNX','A/N','IPComp','SNP','Compaq-Peer','IPX-in-IP','VRRP','PGM','','L2TP','DDX','IATP','STP','SRP','UTI','SMP','SM','PTP','IS-IS over IPv4','FIRE','CRTP','CRUDP','SSCOPMCE','IPLT','SPS','PIPE','SCTP','FC','RSVP-E2E-IGNORE','Mobility Header','UDPLite','MPLS-in-IP','manet','HIP','Shim6','WESP','ROHC','Ethernet']
TEMPLATE_DIR = os.path.abspath('templates')
STATIC_DIR = os.path.abspath('static')

date=TableFromCommand.TableFromCommand('rwsiteinfo --fields=repo-start-date,repo-end-date > repo-date.txt','repo-date.txt')
date=date.execute()
startdate=date.getColumn('Start-Date')[0]
enddate=date.getColumn('End-Date')[0]

startdateFile = ''
enddateFile = ''

app = Flask(__name__, static_folder="static")

app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024
app.config['UPLOAD_EXTENSIONS'] = ['.pcap', '.pcapng']
app.config['UPLOAD_PATH'] = 'uploads'

@app.route('/')
def blankpage():
    return redirect('/singlepathsample')

@app.route('/home', methods = ['GET','POST'])
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
    topFlowByRecordCommand='''rwfilter --start={_startdate} --end={_enddate} --type=in,inweb,out,outweb --proto=0- --pass=stdout|rwstats --count {_counts} --fields sip,dip --values=records --no-columns > topFlowByRecord.txt'''
    topFlowBySizeCommand = '''rwfilter --type all --proto=0- --start={_startdate} --end={_enddate} --pass=stdout | rwstats --count {_counts} --fields sip,dip,bytes  --values=bytes --top --no-columns > topFlowBySize.txt'''
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
        dataset.append(100 - float(topFlowByRecordsTable.getColumn('cumul_%')[-1]))
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

@app.route('/iptoipsearch',methods=['GET'])
def iptoipinit():
    return render_template('iptoipInit.html')

@app.route('/iptoip', methods = ['POST'])
def iptoip():
    global protocols
    _sip = request.form['sip']
    _dip = request.form['dip']
    _counts = request.form['counts']
    command = '''rm iptoip.rw; rwfilter traffic.rw --type=all --pass=iptoip.rw --scidr={sip}/32,{dip}/32 --dcidr={dip}/32,{sip}/32; rwsort iptoip.rw --fields=bytes --reverse | rwuniq --fields=sTime,eTime,sip,sport,dip,dport,bytes --no-columns | head -200 > iptoip.txt'''
    command = command.format(sip = _sip, dip = _dip, counts = _counts)
    table = TableFromCommand.TableFromCommand(command, 'iptoip.txt')
    compareTable = table.execute()
    #by protocol
    command = '''rm iptoip.rw; rwfilter traffic.rw --type=all --pass=iptoip.rw --scidr={sip}/32,{dip}/32 --dcidr={dip}/32,{sip}/32; rwsort iptoip.rw --fields=bytes --reverse | rwstats --count {counts} --fields sip,dip,proto --values=records --no-columns > iptoip.txt'''
    command = command.format(sip = _sip, dip = _dip, counts = _counts)
    table = TableFromCommand.TableFromCommand(command, 'iptoip.txt')
    compareTableByPro = table.execute()
    compareTableByPro.Table['protocol'] = compareTableByPro.Table['protocol'].astype(str)
    for index, row in compareTableByPro.Table.iterrows():
        compareTableByPro.Table.at[index, 'protocol'] = protocols[int(compareTableByPro.Table.at[index, 'protocol']) - 1]
    #by package
    command = '''rm iptoip.rw; rwfilter traffic.rw --type=all --pass=iptoip.rw --scidr={sip}/32,{dip}/32 --dcidr={dip}/32,{sip}/32; rwsort iptoip.rw --fields=bytes --reverse | rwstats --count {counts} --fields sip,dip,sport,dport --values=records --no-columns > iptoip.txt'''
    command = command.format(sip = _sip, dip = _dip, counts = _counts)
    table = TableFromCommand.TableFromCommand(command, 'iptoip.txt')
    compareTableByPackage = table.execute()
    return render_template('iptoip.html', compareTable = compareTable, sip=_sip,dip=_dip, counts = _counts, compareTableByPro=compareTableByPro,compareTableByPackage=compareTableByPackage)

@app.route('/singlepathsample', methods=['GET'])
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

@app.route('/singlepathsample', methods=['POST'])
def singlepathInit():
    global dictionary

    global startdate
    global enddate
    global startdateFile
    global enddateFile
    startdateFile = startdate
    enddateFile = enddate
    params = ''
    if len(request.form['startdate']) == 16:
        temp1 = request.form['startdate'] + ':00'
    else:
        temp1 = request.form['startdate']
    if len(request.form['enddate']) == 16:
        temp2 = request.form['enddate'] + ':00'
    else:
        temp2 = request.form['enddate']
    _startdate = datetime.strptime(temp1,'%Y-%m-%dT%H:%M:%S').strftime('%Y/%m/%dT%H:%M:%S')
    _enddate = datetime.strptime(temp2,'%Y-%m-%dT%H:%M:%S').strftime('%Y/%m/%dT%H:%M:%S')
    _sensor = request.form['sensor']
    global sensor
    sensor = _sensor
    _ip = request.form['ip']
    #init data
    command = 'rm traffic.rw;rwfilter --start={start} --end={end} --sensor={sensor} --type=in,inweb,out,outweb --any-address={ip} --pass=traffic.rw'.format(start=_startdate,end=_enddate,sensor=_sensor,ip=_ip)
    os.chdir('data')
    os.system(command)
    os.chdir('..')
    command = 'rm traffic1.rw;rwfilter --start={start} --end={end} --sensor={sensor} --type=in,inweb,out,outweb --any-address={ip} --pass=traffic1.rw'.format(start=_startdate,end=_enddate,sensor=_sensor,ip=_ip)
    os.chdir('data')
    os.system(command)
    os.chdir('..')
    return redirect(url_for('overall'))

@app.route('/overall', methods=['GET','POST'])
def overall():
    _counts = 20
    if 'counts' in request.form:
        _counts = request.form['counts']
    singlepathanaliser = SinglePath.SinglePath('traffic.rw', _counts)
    binsize = singlepathanaliser.binsize()
    overall = singlepathanaliser.overallview()
    lowbyte = singlepathanaliser.lowbyte()
    medbyte = singlepathanaliser.medbyte()
    highbyte = singlepathanaliser.highbyte()
    shortduration = singlepathanaliser.shortduration()
    medduration = singlepathanaliser.medduration()
    longduration = singlepathanaliser.longduration()
    byte_duration_list = [lowbyte, medbyte, highbyte, shortduration, medduration, longduration]
    labels = list()
    byte_duration_charts = list()
    for dataset in byte_duration_list:
        in_data = list()
        out_data = list()
        inweb_data = list()
        outweb_data = list()
        labels = list()
        rows = dataset.getAllRow()
        checker = 0
        for row in rows:
            if row[0] not in labels:
                if checker != 4:
                    if len(in_data) != len(labels):
                        in_data.append(0)
                    if len(out_data) != len(labels):
                        out_data.append(0)
                    if len(inweb_data) != len(labels):
                        inweb_data.append(0)
                    if len(outweb_data) != len(labels):
                        outweb_data.append(0)
                labels.append(row[0])
                checker = 0
            if row[1] == 'in':
                in_data.append(row[2])
                checker += 1
            elif row[1] == 'out':
                out_data.append(row[2])
                checker += 1
            elif row[1] == 'inweb':
                inweb_data.append(row[2])
                checker += 1
            elif row[1] == 'outweb':
                outweb_data.append(row[2])
                checker += 1
        if len(in_data) != len(labels):
            in_data.append(0)
        if len(out_data) != len(labels):
            out_data.append(0)
        if len(inweb_data) != len(labels):
            inweb_data.append(0)
        if len(outweb_data) != len(labels):
            outweb_data.append(0)
        in_dataset = ChartRender.dataSet('"rgba(255, 98, 0, 1)"',in_data,'"in"')
        out_dataset = ChartRender.dataSet('"rgba(248, 255, 0, 1)"',out_data,'"out"')
        inweb_dataset = ChartRender.dataSet('"rgba(0, 255, 34, 1)"', inweb_data, '"inweb"')
        outweb_dataset = ChartRender.dataSet('"rgba(0, 141, 255, 1)"', outweb_data,'"outweb"')
        chart_data = [in_dataset, out_dataset, inweb_dataset, outweb_dataset]
        chart = ChartRender.barChart()
        chart = chart.barChartRender(labels, chart_data, 'barchart' + str(byte_duration_list.index(dataset)), 'true')
        byte_duration_charts.append(chart)
    protocolTable = overall[1]
    protocolPieChart = ChartRender.customPieChart()
    protocolLabels = protocolTable.getColumn('pro')
    protocolData = protocolTable.getColumn('%Records')
    protocolPieChart = protocolPieChart.customPieChartRender('protocolPieChart', protocolLabels, protocolData)
    
    
    return render_template('singlepathOverall.html', counts=_counts,
    overall = overall, lowbyte = lowbyte, medbyte = medbyte, highbyte = highbyte, shortduration = shortduration, medduration = medduration, longduration = longduration, binsize = binsize,
    byte_duration_charts = byte_duration_charts, protocolPieChart = protocolPieChart)

@app.route('/singlepathdetail',methods=['GET'])
def singlepathdetailInit():
    return render_template('singlepathdetailInit.html')

@app.route('/singlepathdetailIP', methods=['GET'])
def singlepathdetailIP():
    _counts = 20
    _ip = request.args['ip']
    if 'counts' in request.args and request.args['counts'] != '':
        _counts = request.args['counts']
    command = 'rwfilter traffic.rw --saddress={ip} --type=out,outweb --pass=stdout | rwstats --fields=dip,dport --count {counts} > saddress.txt'.format(ip=_ip, counts=_counts)
    saddressTable = TableFromCommand.TableFromCommand(command, 'saddress.txt')
    saddressTable = saddressTable.execute()
    command = 'rwfilter traffic.rw --daddress={ip} --type=in,inweb --pass=stdout | rwstats --fields=sip,sport --count {counts} > daddress.txt'.format(ip=_ip, counts=_counts)
    daddressTable = TableFromCommand.TableFromCommand(command, 'daddress.txt')
    daddressTable = daddressTable.execute()

    return render_template('singlepathDetail.html',
    counts = _counts, ip = _ip,
    saddressTable=saddressTable,daddressTable=daddressTable)

@app.route("/upload", methods = ['GET'])
def uploadFile():
    return render_template('upload.html')

@app.route('/uploader', methods = ['POST'])
def uploader():
    uploaded_file = request.files['fileupload']
    filename = secure_filename(uploaded_file.filename)
    if filename != '':
        file_ext = os.path.splitext(filename)[1]
        if file_ext not in app.config['UPLOAD_EXTENSIONS']:
            abort(400)
        uploaded_file.save(os.path.join(app.config['UPLOAD_PATH'], filename))

    
    
    return redirect(url_for('uploadFile'))

@app.route("/analyseUpload", methods=['GET'])
def analyseUploadChoseFile():
    files = os.listdir('uploads')
    filelist = list()
    for file in files:
        if file.endswith('.pcap') or file.endswith('.pcapng'):
            filelist.append(file)
    global startdateFile
    global enddateFile
    startdateFile,enddateFile = readPCAP.PCAPHandle(filelist[0]).getdate()
    return render_template('analyseUploadChoseFile.html', files=filelist,
    startdate=datetime.strptime(startdateFile,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'), 
    enddate=datetime.strptime(enddateFile,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'))

@app.route('/realtime')
def realtime():
    os.chdir('data')
    command = 'rm traffic.rw; rm traffic.yaf;yaf --in {file} --out traffic.yaf; rwipfix2silk traffic.yaf --silk-output=traffic.rw'.format(file='realtime.pcap')
    os.system(command)
    os.chdir('..')
    return redirect('/overall')

@app.route('/graphic', methods=['GET'])
def graphic():
    global dictionary
    allowip = list()
    allowport = list()
    if 'ips' in request.args and request.args['ips'] != '':
        ips = request.args['ips']
        ips = ips.split(',')
        for ip in ips:
            if ip not in allowip:
                allowip.append(ip)
    if 'ports' in request.args and request.args['ports'] != '':
        ports = request.args['ports']
        ports = ports.split(',')
        for port in ports:
            if '-' not in port:
                if port not in allowport:
                    allowport.append(port)
            if '-' in port:
                portrange = port.split('-')
                for i in range(int(portrange[0]), int(portrange[1]) + 1):
                    if port not in allowport:
                        allowport.append(i)
    os.chdir('data')
    command = 'rwfilter traffic.rw --type=in --pass=stdout | rwuniq --fields=sip,sport > source_ingraphic.txt'
    os.system(command)
    command = 'rwfilter traffic.rw --type=in --pass=stdout | rwuniq --fields=dip,dport > destination_ingraphic.txt'
    os.system(command)
    command = 'rwfilter traffic.rw --type=in --pass=stdout | rwstats --fields=sip --count=20 > sip_ingraphic.txt'
    os.system(command)
    command = 'rwfilter traffic.rw --type=in --pass=stdout | rwstats --fields=dip --count=20 > dip_ingraphic.txt'
    os.system(command)
    os.chdir('..')
    graphic = Graphic.Graphic('sip_ingraphic.txt', 'dip_ingraphic.txt', 'source_ingraphic.txt', 'destination_ingraphic.txt')
    graphic.render('ingraphic', 'Sensor', dictionary, allowip, allowport)
    os.chdir('data')
    command = 'rwfilter traffic.rw --type=inweb --pass=stdout | rwuniq --fields=sip,sport > source_inwebgraphic.txt'
    os.system(command)
    command = 'rwfilter traffic.rw --type=inweb --pass=stdout | rwuniq --fields=dip,dport > destination_inwebgraphic.txt'
    os.system(command)
    command = 'rwfilter traffic.rw --type=inweb --pass=stdout | rwstats --fields=sip --count=20 > sip_inwebgraphic.txt'
    os.system(command)
    command = 'rwfilter traffic.rw --type=inweb --pass=stdout | rwstats --fields=dip --count=20 > dip_inwebgraphic.txt'
    os.system(command)
    os.chdir('..')
    graphic = Graphic.Graphic('sip_inwebgraphic.txt', 'dip_inwebgraphic.txt', 'source_inwebgraphic.txt', 'destination_inwebgraphic.txt')
    graphic.render('inwebgraphic', 'Sensor', dictionary, allowip, allowport)
    os.chdir('data')
    command = 'rwfilter traffic.rw --type=out --pass=stdout | rwuniq --fields=sip,sport > source_outgraphic.txt'
    os.system(command)
    command = 'rwfilter traffic.rw --type=out --pass=stdout | rwuniq --fields=dip,dport > destination_outgraphic.txt'
    os.system(command)
    command = 'rwfilter traffic.rw --type=out --pass=stdout | rwstats --fields=sip --count=20 > sip_outgraphic.txt'
    os.system(command)
    command = 'rwfilter traffic.rw --type=out --pass=stdout | rwstats --fields=dip --count=20 > dip_outgraphic.txt'
    os.system(command)
    os.chdir('..')
    graphic = Graphic.Graphic('sip_outgraphic.txt', 'dip_outgraphic.txt', 'source_outgraphic.txt', 'destination_outgraphic.txt')
    graphic.render('outgraphic', 'Sensor', dictionary, allowip, allowport)
    os.chdir('data')
    command = 'rwfilter traffic.rw --type=outweb --pass=stdout | rwuniq --fields=sip,sport > source_outwebgraphic.txt'
    os.system(command)
    command = 'rwfilter traffic.rw --type=outweb --pass=stdout | rwuniq --fields=dip,dport > destination_outwebgraphic.txt'
    os.system(command)
    command = 'rwfilter traffic.rw --type=outweb --pass=stdout | rwstats --fields=sip --count=20 > sip_outwebgraphic.txt'
    os.system(command)
    command = 'rwfilter traffic.rw --type=outweb --pass=stdout | rwstats --fields=dip --count=20 > dip_outwebgraphic.txt'
    os.system(command)
    os.chdir('..')
    graphic = Graphic.Graphic('sip_outwebgraphic.txt', 'dip_outwebgraphic.txt', 'source_outwebgraphic.txt', 'destination_outwebgraphic.txt')
    graphic.render('outwebgraphic', 'Sensor', dictionary, allowip, allowport)
    return render_template('download.html')

@app.route('/download', methods = ['GET'])
def download():
    path = request.args['file']
    return send_file(path, as_attachment=True)

@app.route('/file', methods=['GET'])
def modifyFile():
    global startdateFile
    global enddateFile
    startdatecmd = 'rwsort traffic.rw --fields=stime --output-path=stdout | rwcut --no-columns| head -2 > getstart.txt'
    enddatecmd = 'rwsort traffic.rw --fields=etime --reverse --output-path=stdout | rwcut --no-columns| head -2 > getend.txt'
    start = TableFromCommand.TableFromCommand(startdatecmd, 'getstart.txt')
    start = start.execute()
    end = TableFromCommand.TableFromCommand(enddatecmd, 'getend.txt')
    end = end.execute()
    start = str(start.getColumn('sTime')[0]).split('.')[0]
    start = datetime.strptime(start,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S')
    end = str(end.getColumn('eTime')[0]).split('.')[0]
    end = datetime.strptime(end,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S')
    startdateFile = start
    enddateFile = end
    return render_template('modifyFile.html',
    startdate=start,enddate=end)

@app.route('/initfile', methods=['GET'])
def initfile():
    global dictionary
    global startdateFile
    global enddateFile
    filename = request.args['chosedfile']    
    current = os.getcwd()
    filelink = current + '/uploads/' + filename
    command = 'rm traffic.rw; rm traffic.yaf;yaf --in {file} --out traffic.yaf --ip4-only; rwipfix2silk traffic.yaf --silk-output=traffic.rw'.format(file=filelink)
    os.chdir('data')
    os.system(command)
    os.chdir('..')
    command = 'rm traffic1.rw; rm traffic1.yaf;yaf --in {file} --out traffic1.yaf --ip4-only; rwipfix2silk traffic1.yaf --silk-output=traffic1.rw'.format(file=filelink)
    os.chdir('data')
    os.system(command)
    os.chdir('..')
    
    pcap = readPCAP.PCAPHandle(filename)
    if pcap.count() > 0:
        _startdate,_enddate = pcap.getdate()
        startdateFile = _startdate
        enddateFile = _enddate
    dictionary = pcap.match()
    return redirect('/overall')
@app.route('/modifyRange', methods=["GET"])
def modifyRange():
    global startdateFile
    global enddateFile
    return render_template('modifyFile.html',
    startdate=datetime.strptime(startdateFile,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'), 
    enddate=datetime.strptime(enddateFile,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'))

@app.route('/modify', methods=['POST'])
def modify():
    _sip = ''
    _dip = ''
    _sport = ''
    _dport = ''
    _startdate = ''
    _enddate = ''
    params = ''
    if 'sip' in request.form  and request.form['sip'] != '':
        _sip = request.form['sip']
        params += ' --saddress=' + _sip.strip()
    if 'dip' in request.form  and request.form['dip'] != '':
        _dip = request.form['dip']
        params += ' --daddress=' + _dip.strip()
    if 'sport' in request.form  and request.form['sport'] != '':
        _sport = request.form['sport']
        params += ' --sport=' + _sport.strip()
    if 'dport' in request.form  and request.form['dport'] != '':
        _dport = request.form['dport']
        params += ' --dport=' + _dport.strip()
    if 'startdate' in request.form and request.form['startdate'] != '':
        if len(request.form['startdate']) == 16:
            _startdate = request.form['startdate'] + ':00'
        else:
            _startdate = request.form['startdate']
        _startdate = datetime.strptime(_startdate,'%Y-%m-%dT%H:%M:%S').strftime('%Y/%m/%dT%H:%M:%S')
    if 'enddate' in request.form  and request.form['enddate'] != '':
        if len(request.form['enddate']) == 16:
            _enddate = request.form['enddate'] + ':00'
        else:
            _enddate = request.form['enddate']
        _enddate = datetime.strptime(_enddate,'%Y-%m-%dT%H:%M:%S').strftime('%Y/%m/%dT%H:%M:%S')
    if _startdate != '' and _enddate != '':
        params += " --stime={start}-{end} --etime={start}-{end}".format(start=_startdate,end=_enddate)
    command = 'rm traffic.rw;rwfilter traffic1.rw {params} --type=in,inweb,out,outweb --pass=traffic.rw'.format(params = params)
    os.chdir('data')
    os.system(command)
    os.chdir('..')
    return redirect('/overall')

@app.route('/getdate', methods=['POST'])
def getdate():
    filename = request.form['filename']
    pcapFile = readPCAP.PCAPHandle(filename)
    _startdate,_enddate = pcapFile.getdate()
    return jsonify({'startdate': _startdate,'enddate': _enddate})

@app.route('/multipathscan', methods=['POST','GET'])
def multipathscan():
    global startdate
    global enddate
    _startdate = startdate
    _enddate = enddate
    if 'startdate' in request.form:
        _startdate = request.form['startdate']
        if len(_startdate) < 17:
            _startdate += ':00'
        _startdate = datetime.strptime(_startdate,'%Y-%m-%dT%H:%M:%S').strftime('%Y/%m/%dT%H:%M:%S')
    if 'enddate' in request.form:
        _enddate = request.form['enddate']
        if len(_enddate) < 17:
            _enddate += ':00'
        _enddate = datetime.strptime(_enddate,'%Y-%m-%dT%H:%M:%S').strftime('%Y/%m/%dT%H:%M:%S')
    DetectingScanningcommand = '''rwfilter --start={_startdate} --end={_enddate} --proto=6 --type=in,inweb --pass=stdout | rwsort --fields=sip,proto,dip | rwscan --scan-model=2 --no-columns > scan.txt''' 
    DetectingScanningcommand = DetectingScanningcommand.format(_startdate=_startdate,_enddate=_enddate)
    DetectingScanningtable = TableFromCommand.TableFromCommand(DetectingScanningcommand, 'scan.txt')
    DetectingScanningtable = DetectingScanningtable.execute()
    return render_template('multipathScan.html',
    DetectingScanningtable=DetectingScanningtable, 
    startdate=datetime.strptime(startdate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'), 
    enddate=datetime.strptime(enddate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'),
    _startdate=datetime.strptime(_startdate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'),
    _enddate=datetime.strptime(_enddate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'))
@app.route('/multipathip', methods=['POST', 'GET'])
def multipathsip():
    global startdate
    global enddate
    _startdate = startdate
    _enddate = enddate
    _protocol = 6
    _counts = 5
    _sensor = '--sensor='
    _num = 'all'
    # _ip = request.form['ip']
    _ip = request.args.get('ip')
    if 'sensor' in request.args:
        _num = request.args.get('sensor')
        _sensor = _sensor + _num
    if 'protocol' in request.args:
        _protocol = request.args.get('protocol')
    if 'startdate' in request.form:
        _startdate = request.form['startdate']
        if len(_startdate) < 17:
            _startdate += ':00'
        _startdate = datetime.strptime(_startdate,'%Y-%m-%dT%H:%M:%S').strftime('%Y/%m/%dT%H:%M:%S')
    if 'enddate' in request.form:
        _enddate = request.form['enddate']
        if len(_enddate) < 17:
            _enddate += ':00'
        _enddate = datetime.strptime(_enddate,'%Y-%m-%dT%H:%M:%S').strftime('%Y/%m/%dT%H:%M:%S')
    if 'protocol' in request.form:
        _protocol = request.form['protocol']
    if 'sensor' in request.form:
        _num = request.form['sensor']
        _sensor = _sensor + _num
    if 'counts' in request.form:
        _counts = int(request.form['counts'])
    os.chdir('data')
    Command0 = '''rm query.rw response.rw'''
    Command1 = '''rwfilter --type=in,out --start={_startdate} --end={_enddate} --protocol={_protocol} --saddr={_ip} --pass=stdout | rwsort --fields=2,3,4,stime --output-path=query.rw'''
    Command2 = '''rwfilter --type=in,out --start={_startdate} --end={_enddate} --protocol={_protocol} --daddr={_ip} --pass=stdout | rwsort --fields=1,4,3,stime --output-path=response.rw'''
    Command1 = Command1.format(_startdate=_startdate,_enddate=_enddate,_protocol=_protocol,_ip=_ip)
    Command2 = Command2.format(_startdate=_startdate,_enddate=_enddate,_protocol=_protocol,_ip=_ip)
    if _num != 'all':
        Command1 = '''rwfilter --type=in,out --start={_startdate} --end={_enddate} --protocol={_protocol} --saddr={_ip} {_sensor} --pass=stdout | rwsort --fields=2,3,4,stime --output-path=query.rw'''
        Command2 = '''rwfilter --type=in,out --start={_startdate} --end={_enddate} --protocol={_protocol} --daddr={_ip} {_sensor} --pass=stdout | rwsort --fields=1,4,3,stime --output-path=response.rw'''
        Command1 = Command1.format(_startdate=_startdate,_enddate=_enddate,_protocol=_protocol,_ip=_ip,_sensor=_sensor)
        Command2 = Command2.format(_startdate=_startdate,_enddate=_enddate,_protocol=_protocol,_ip=_ip,_sensor=_sensor)
    os.system(Command0)
    os.system(Command1)

    os.system(Command2)
    os.chdir('..')
    Datacommand = '''rwmatch --relate=1,2 --relate=2,1 --relate=3,4 --relate=4,3 query.rw response.rw stdout | rwcut --fields=1-4,sen,stime,etime,packets,bytes --num-recs={_counts} --no-columns>flowrelas.txt'''
    Datacommand = Datacommand.format(_counts=_counts)
    Datatable = TableFromCommand.TableFromCommand(Datacommand,'flowrelas.txt')
    Datatable = Datatable.execute()
    return render_template('multipathIP.html',
    Datatable=Datatable,
    startdate=datetime.strptime(startdate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'), 
    enddate=datetime.strptime(enddate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'),
    _startdate=datetime.strptime(_startdate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'),
    _enddate=datetime.strptime(_enddate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'),
    counts=_counts, protocol=_protocol, ip=_ip,num=_num
    )
@app.route('/multipathstatistic', methods=['POST', 'GET'])
def multipathstatistic(): 
    global startdate
    global enddate
    _startdate = startdate
    _enddate = enddate 
    _counts =10 
    
    if 'startdate' in request.form:
        _startdate = request.form['startdate']
        if len(_startdate) < 17:
            _startdate += ':00'
        _startdate = datetime.strptime(_startdate,'%Y-%m-%dT%H:%M:%S').strftime('%Y/%m/%dT%H:%M:%S')
    if 'enddate' in request.form:
        _enddate = request.form['enddate']
        if len(_enddate) < 17:
            _enddate += ':00'
        _enddate = datetime.strptime(_enddate,'%Y-%m-%dT%H:%M:%S').strftime('%Y/%m/%dT%H:%M:%S')
    if 'counts' in request.form:
        _counts = int(request.form['counts'])
    Datacommand = '''rm in_month.rw;rwfilter --start={_startdate} --end={_enddate} --type=in,inweb --protocol=0- --pass=stdout --pass=in_month.rw | rwstats --field=sip,sport --value=flows --count {_counts} --no-columns >multistatistic.txt'''
    Datacommand = Datacommand.format(_startdate=_startdate,_enddate=_enddate,_counts=_counts)
    Datatable = TableFromCommand.TableFromCommand(Datacommand,'multistatistic.txt')
    Datatable = Datatable.execute()
    
    return render_template('multipathStatistic.html',
    Datatable=Datatable,
    startdate=datetime.strptime(startdate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'), 
    enddate=datetime.strptime(enddate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'),
    _startdate=datetime.strptime(_startdate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'),
    _enddate=datetime.strptime(_enddate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'),
    counts=_counts  
    )
@app.route('/multipathtcp', methods=['POST', 'GET'])
def multipathtcp(): 
    global startdate
    global enddate
    _startdate = startdate
    _enddate = enddate 
    _counts = 10 
    _sensor = 'S5'
    if 'startdate' in request.form:
        _startdate = request.form['startdate']
        if len(_startdate) < 17:
            _startdate += ':00'
        _startdate = datetime.strptime(_startdate,'%Y-%m-%dT%H:%M:%S').strftime('%Y/%m/%dT%H:%M:%S')
    if 'enddate' in request.form:
        _enddate = request.form['enddate']
        if len(_enddate) < 17:
            _enddate += ':00'
        _enddate = datetime.strptime(_enddate,'%Y-%m-%dT%H:%M:%S').strftime('%Y/%m/%dT%H:%M:%S')
    if 'counts' in request.form:
        _counts = int(request.form['counts'])  
    if 'sensor' in request.form:
        _sensor = request.form['sensor']
    Command0 = '''rm incoming-server.raw incoming-client.raw outgoing-server.raw outgoing-client.raw leftover.raw;rwfilter --start={_startdate} --end={_enddate} --sensor={_sensor} --type=in,out --protocol=6 --packets=3- --pass=stdout | rwfilter stdin --type=in --flags-initial=SA/SA --pass=incoming-server.raw --fail=stdout | rwfilter stdin --type=in --flags-initial=S/SA --pass=incoming-client.raw --fail=stdout | rwfilter stdin --type=out --flags-initial=SA/SA --pass=outgoing-server.raw --fail=stdout | rwfilter stdin --type=out --flags-initial=S/SA --pass=outgoing-client.raw --fail=leftover.raw'''
    Command1 = '''rm lowpacket.rw synonly.rw reset.rw;rwfilter --start={_startdate} --end={_enddate} --type=in,inweb --protocol=6 --packets=1-3 --pass=lowpacket.rw --pass=stdout | rwfilter --flags-all=S/SARF --pass=synonly.rw --fail=stdout stdin | rwfilter --flags-all=R/SRF --pass=reset.rw stdin'''
    Command1 = Command1.format(_startdate=_startdate,_enddate=_enddate)
    os.chdir('data')
    Command0 = Command0.format(_startdate=_startdate,_enddate=_enddate,_sensor=_sensor)
    os.system(Command0)
    os.system(Command1)
    os.chdir('..')
    Datacommand0 = '''rwcut incoming-server.raw --fields=1-4,stime,etime --num-recs={_counts} --no-columns>incoming-server.txt'''
    Datacommand1 = '''rwcut incoming-client.raw --fields=1-4,stime,etime --num-recs={_counts} --no-columns>incoming-client.txt'''
    Datacommand2 = '''rwcut outgoing-server.raw --fields=1-4,stime,etime --num-recs={_counts} --no-columns>outgoing-server.txt'''
    Datacommand3 = '''rwcut outgoing-client.raw --fields=1-4,stime,etime --num-recs={_counts} --no-columns>outgoing-client.txt'''
    Datacommand4 = '''rwcut leftover.raw --fields=1-4,stime,etime --num-recs={_counts} --no-columns>leftover.txt'''
    Datacommand5 = '''rwcut lowpacket.rw --fields=1-4,sensor,stime,etime --num-recs={_counts} --no-columns>lowpacket.txt'''
    Datacommand6 = '''rwcut synonly.rw --fields=1-4,sensor,stime,etime --num-recs={_counts} --no-columns>synonly.txt'''
    Datacommand7 = '''rwcut reset.rw --fields=1-4,sensor,stime,etime --num-recs={_counts} --no-columns>reset.txt'''

    Datacommand0 = Datacommand0.format(_counts=_counts)
    Datacommand1 = Datacommand1.format(_counts=_counts)
    Datacommand2 = Datacommand2.format(_counts=_counts)
    Datacommand3 = Datacommand3.format(_counts=_counts)
    Datacommand4 = Datacommand4.format(_counts=_counts)
    Datacommand5 = Datacommand5.format(_counts=_counts)
    Datacommand6 = Datacommand6.format(_counts=_counts)
    Datacommand7 = Datacommand7.format(_counts=_counts)

    Datatable0 = TableFromCommand.TableFromCommand(Datacommand0,'incoming-server.txt')
    Datatable0 = Datatable0.execute()
    Datatable1 = TableFromCommand.TableFromCommand(Datacommand1,'incoming-client.txt')
    Datatable1 = Datatable1.execute()
    Datatable2 = TableFromCommand.TableFromCommand(Datacommand2,'outgoing-server.txt')
    Datatable2 = Datatable2.execute()
    Datatable3 = TableFromCommand.TableFromCommand(Datacommand3,'outgoing-client.txt')
    Datatable3 = Datatable3.execute()
    Datatable4 = TableFromCommand.TableFromCommand(Datacommand4,'leftover.txt')
    Datatable4 = Datatable4.execute()
    Datatable5 = TableFromCommand.TableFromCommand(Datacommand5,'lowpacket.txt')
    Datatable5 = Datatable5.execute()
    Datatable6 = TableFromCommand.TableFromCommand(Datacommand6,'synonly.txt')
    Datatable6 = Datatable6.execute()
    Datatable7 = TableFromCommand.TableFromCommand(Datacommand7,'reset.txt')
    Datatable7 = Datatable7.execute()

    return render_template('multipathTCP.html',
    Datatable0=Datatable0,Datatable1=Datatable1,Datatable2=Datatable2,Datatable3=Datatable3,Datatable4=Datatable4,
    Datatable5=Datatable5,Datatable6=Datatable6,Datatable7=Datatable7,
    startdate=datetime.strptime(startdate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'), 
    enddate=datetime.strptime(enddate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'),
    _startdate=datetime.strptime(_startdate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'),
    _enddate=datetime.strptime(_enddate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'),
    counts=_counts,sensor=_sensor
    )
@app.route('/multipathdns', methods=['POST', 'GET'])
def multipathdns(): 
    global startdate
    global enddate
    _startdate = startdate
    _enddate = enddate 
    _counts =10 
    
    if 'startdate' in request.form:
        _startdate = request.form['startdate']
        if len(_startdate) < 17:
            _startdate += ':00'
        _startdate = datetime.strptime(_startdate,'%Y-%m-%dT%H:%M:%S').strftime('%Y/%m/%dT%H:%M:%S')
    if 'enddate' in request.form:
        _enddate = request.form['enddate']
        if len(_enddate) < 17:
            _enddate += ':00'
        _enddate = datetime.strptime(_enddate,'%Y-%m-%dT%H:%M:%S').strftime('%Y/%m/%dT%H:%M:%S')
    if 'counts' in request.form:
        _counts = int(request.form['counts'])
    Command0 = '''rm in_month.rw interest.set;rwfilter --start={_startdate} --end={_enddate} --type=in,inweb --protocol=0- --pass=in_month.rw; rwfilter in_month.rw --protocol=17 --aport=53 --pass=stdout | rwset --sip-file=interest.set'''
    Command0 = Command0.format(_startdate=_startdate,_enddate=_enddate)
    Command1 = '''rm not-dns.rw dns-saddr.txt;rwfilter in_month.rw --sipset=interest.set --protocol=17 --pass=stdout | rwfilter stdin --aport=53 --fail=not-dns.rw --pass=stdout | rwuniq --fields=sIP --no-titles --ip-format=zero-padded --sort-output --no-columns --output-path=dns-saddr.txt'''
    Command2 = '''rm not-dns-saddr.txt;rwuniq not-dns.rw --fields=sip --no-titles --ip-format=zero-padded --sort-output --no-columns --output-path=not-dns-saddr.txt'''
    os.chdir('data')
    os.system(Command0)
    os.system(Command1)
    os.system(Command2)
    os.chdir('..')
    Datacommand = '''rm dns-temp.txt;echo 'sIP|DNS||not DNS|' >dns.txt;join -t '|' dns-saddr.txt not-dns-saddr.txt | sort -t '|' -nrk2,2 | head -{_counts}>dns_temp.txt;cat dns_temp.txt>>dns.txt'''
    Datacommand = Datacommand.format(_counts=_counts)
    Datatable = TableFromCommand.TableFromCommand(Datacommand,'dns.txt')
    Datatable = Datatable.execute()
    
    return render_template('multipathDNS.html',
    Datatable=Datatable,
    startdate=datetime.strptime(startdate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'), 
    enddate=datetime.strptime(enddate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'),
    _startdate=datetime.strptime(_startdate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'),
    _enddate=datetime.strptime(_enddate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'),
    counts=_counts)

@app.route('/singlegraphicinit')
def singlePathGraphicInit():
    return render_template('singlePathGraphic.html')

if __name__ == '__main__':
    app.run(debug = True, host='0.0.0.0', port='2222')
   
