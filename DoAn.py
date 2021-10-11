
from flask.sessions import NullSession
from werkzeug.utils import secure_filename
from itertools import count
from flask import Flask, redirect, url_for, render_template, request, abort
import TableFromFile
import TableFromCommand
import os
import ChartRender
import asyncio
from datetime import datetime
import SinglePath
import pandas as pd

protocols = ['ICMP','IGMP','GGP','IP-in-IP','ST','TCP','CBT','EGP','IGP','BBN-RCC-MON','NVP-II','PUP','ARGUS','EMCON','XNET','CHAOS','UDP','MUX','DCN-MEAS','HMP','PRM','XNS-IDP','TRUNK-1','TRUNK-2','LEAF-1','LEAF-2','RDP','IRTP','ISO-TP4','NETBLT','MFE-NSP','MERIT-INP','DCCP','3PC','IDPR','XTP','DDP','IDPR-CMTP','TP++','IL','IPv6','SDRP','IPv6-Route','IPv6-Frag','IDRP','RSVP','GRE','DSR','BNA','ESP','AH','I-NLSP','SwIPe','NARP','MOBILE','TLSP','SKIP','IPv6-ICMP','IPv6-NoNxt','IPv6-Opts','','CFTP','','SAT-EXPAK','KRYPTOLAN','RVD','IPPC','','SAT-MON','VISA','IPCU','CPNX','CPHB','WSN','PVP','BR-SAT-MON','SUN-ND','WB-MON','WB-EXPAK','ISO-IP','VMTP','SECURE-VMTP','VINES','TTP','IPTM','NSFNET-IGP','DGP','TCF','EIGRP','OSPF','Sprite-RPC','LARP','MTP','AX.25','OS','MICP','SCC-SP','ETHERIP','ENCAP','','GMTP','IFMP','PNNI','PIM','ARIS','SCPS','QNX','A/N','IPComp','SNP','Compaq-Peer','IPX-in-IP','VRRP','PGM','','L2TP','DDX','IATP','STP','SRP','UTI','SMP','SM','PTP','IS-IS over IPv4','FIRE','CRTP','CRUDP','SSCOPMCE','IPLT','SPS','PIPE','SCTP','FC','RSVP-E2E-IGNORE','Mobility Header','UDPLite','MPLS-in-IP','manet','HIP','Shim6','WESP','ROHC','Ethernet']
TEMPLATE_DIR = os.path.abspath('templates')
STATIC_DIR = os.path.abspath('static')

date=TableFromCommand.TableFromCommand('rwsiteinfo --fields=repo-start-date,repo-end-date > repo-date.txt','repo-date.txt')
date=date.execute()
startdate=date.getColumn('Start-Date')[0]
enddate=date.getColumn('End-Date')[0]

app = Flask(__name__, static_folder="static")

app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024
app.config['UPLOAD_EXTENSIONS'] = ['.pcap', '.pcapng']
app.config['UPLOAD_PATH'] = 'uploads'

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
    _startdate = datetime.strptime(request.form['startdate'] + ':00','%Y-%m-%dT%H:%M:%S').strftime('%Y/%m/%dT%H:%M:%S')
    _enddate = datetime.strptime(request.form['enddate'] + ':00','%Y-%m-%dT%H:%M:%S').strftime('%Y/%m/%dT%H:%M:%S')
    
    _sensor = request.form['sensor']
    _ip = request.form['ip']
    #init data
    command = 'rm traffic.rw;rwfilter --start={start} --end={end} --sensor={sensor} --type=in,inweb,out,outweb --any-address={ip} --pass=traffic.rw'.format(start=_startdate,end=_enddate,sensor=_sensor,ip=_ip)
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
    return render_template('analyseUploadChoseFile.html', files=filelist)

@app.route('/initfile', methods=['GET'])
def initfile():
    filename = request.args['chosedfile']
    current = os.getcwd()
    filelink = current + '/uploads/' + filename
    command = 'rm traffic.rw; rm traffic.yaf;yaf --in {file} --out traffic.yaf; rwipfix2silk traffic.yaf --silk-output=traffic.rw'.format(file=filelink)
    os.chdir('data')
    os.system(command)
    os.chdir('..')
    return redirect('/overall')

@app.route('/realtime')
def realtime():
    os.chdir('data')
    command = 'rm traffic.rw; rm traffic.yaf;yaf --in {file} --out traffic.yaf; rwipfix2silk traffic.yaf --silk-output=traffic.rw'.format(file='realtime.pcap')
    os.system(command)
    os.chdir('..')
    return redirect('/overall')
@app.route('/multipathscan', methods=['POST','GET'])
def multipathscan():
    global startdate
    global enddate
    _startdate = startdate
    _enddate = enddate
    if 'startdate' in request.form:
        _startdate = datetime.strptime(request.form['startdate'],'%Y-%m-%dT%H:%M:%S').strftime('%Y/%m/%dT%H:%M:%S')
    if 'enddate' in request.form:
        _enddate = datetime.strptime(request.form['enddate'],'%Y-%m-%dT%H:%M:%S').strftime('%Y/%m/%dT%H:%M:%S')
    # create command and data
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
    _protocol = '6'
    _protocols = list()
    _check = list()
    allproto = ' '
    _paraIP1 = ''
    _paraIP2 = ''
    for num in range(len(protocols)):
        _check.append(' ')
    _counts = 10
    _sensor = '--sensor='
    _num = 'all'
    _dip = ''
    _sip = ''
    if 'sip' in request.args:
        _sip = request.args.get('sip')
        _paraIP1+='--saddr='+_sip
        _paraIP2+='--daddr='+_sip
    if 'dip' in request.args:
        _dip = request.args.get('dip')
        _paraIP1+=' --dadrr='+_dip
        _paraIP2+='--saddr='+_dip
    if 'sensor' in request.args:
        _num = request.args.get('sensor')
        _sensor = _sensor + _num
       
    if 'startdate' in request.form:
        _startdate = datetime.strptime(request.form['startdate'] ,'%Y-%m-%dT%H:%M:%S').strftime('%Y/%m/%dT%H:%M:%S')
    if 'enddate' in request.form:
        _enddate = datetime.strptime(request.form['enddate'] ,'%Y-%m-%dT%H:%M:%S').strftime('%Y/%m/%dT%H:%M:%S')
    if 'protocol' in request.args:
        _protocol = request.args.get('protocol')
    if _protocol == '0-' or request.form.get('allproto'):
        allproto = 'checked'
        for num in range(len(protocols)):               
            _check[num] = 'checked'
    else:
        if len(request.form.getlist('protocols'))!=len(protocols)-5 and len(request.form.getlist('protocols'))!=0:
                _protocols = request.form.getlist('protocols')
                _protocol = ''
                for x in _protocols:
                    _protocol+= str(protocols.index(x)+1)
                    _check[int(protocols.index(x))]='checked'
                    if _protocols.index(x)< len(_protocols)-1:
                        _protocol+=','
        else:
            _check[int(_protocol)-1]='checked'

    if 'sensor' in request.form:
        _num = request.form['sensor']
        _sensor = _sensor + _num
    if 'counts' in request.form:
        _counts = int(request.form['counts'])
    if 'sip' in request.form:
        _sip = request.form['sip']
        if _sip!='':
            _paraIP1+='--saddr='+_sip.strip()
            _paraIP2+='--daddr='+_sip.strip()
    if 'dip' in request.form:
        _dip = request.form['dip']
        if _dip!='':
            _paraIP1+=' --daddr='+_dip.strip()
            _paraIP2+=' --saddr='+_dip.strip()
    # create command and data
    os.chdir('data')
    Command0 = '''rm query.rw response.rw'''
    Command1 = '''rwfilter --type=in,out --start={_startdate} --end={_enddate} --protocol={_protocol} {_paraIP1} --pass=stdout | rwsort --fields=1,2,3,4,stime --output-path=query.rw'''
    Command2 = '''rwfilter --type=in,out --start={_startdate} --end={_enddate} --protocol={_protocol} {_paraIP2} --pass=stdout | rwsort --fields=2,1,4,3,stime --output-path=response.rw'''
    Command1 = Command1.format(_startdate=_startdate,_enddate=_enddate,_protocol=_protocol,_paraIP1=_paraIP1)
    Command2 = Command2.format(_startdate=_startdate,_enddate=_enddate,_protocol=_protocol,_paraIP2=_paraIP2)
    if _num != 'all':
        Command1 = '''rwfilter --type=in,out --start={_startdate} --end={_enddate} --protocol={_protocol} {_paraIP1} {_sensor} --pass=stdout | rwsort --fields=1,2,3,4,stime --output-path=query.rw'''
        Command2 = '''rwfilter --type=in,out --start={_startdate} --end={_enddate} --protocol={_protocol} {_paraIP2} {_sensor} --pass=stdout | rwsort --fields=2,1,4,3,stime --output-path=response.rw'''
        Command1 = Command1.format(_startdate=_startdate,_enddate=_enddate,_protocol=_protocol,_paraIP1=_paraIP1,_sensor=_sensor)
        Command2 = Command2.format(_startdate=_startdate,_enddate=_enddate,_protocol=_protocol,_paraIP2=_paraIP2,_sensor=_sensor)
    os.system(Command0)
    os.system(Command1)

    os.system(Command2)
    os.chdir('..')
    # match flow and create data
    Datacommand = '''rwmatch --relate=1,2 --relate=2,1 --relate=3,4 --relate=4,3 query.rw response.rw stdout | rwcut --fields=1-4,sen,proto,flag,stime,etime,packets,bytes --num-recs={_counts} --no-columns>flowrelas.txt'''
    Datacommand = Datacommand.format(_counts=_counts)
    Datatable = TableFromCommand.TableFromCommand(Datacommand,'flowrelas.txt')
    Datatable = Datatable.execute()

    # data for chart
    Datacommand1 = '''rwstats query.rw --fields=1,2 --values=flows --count=10 --no-columns>query.txt'''
    Datacommand2 = '''rwstats response.rw --fields=1,2 --values=flows --count=10 --no-columns>response.txt'''
    Datatable1 = TableFromCommand.TableFromCommand(Datacommand1,'query.txt')
    Datatable2 = TableFromCommand.TableFromCommand(Datacommand2,'response.txt')
    Datatable1 = Datatable1.execute()
    Datatable2 = Datatable2.execute()

    # draw chart1
    rows = Datatable1.getAllRow()
    red = 0
    green = 0
    blue = 0
    Datachart = list()
    Datachartpie = list()
    for row in rows:
        label = row[0]+'->'+row[1]
        data = list()
        data.append(row[2])
        Datachartpie.append(row[3])
        if red < 250:
            red += 50
        else:
            if green < 250:
                green += 50
            else:
                if blue < 250:
                    blue += 50
        color = '"rgba({red}, {green}, {blue}, 1)"'
        color = color.format(red=red, green=green, blue=blue)
        dataset = ChartRender.dataSet(color,data, '"'+ label + '"')
        Datachart.append(dataset)
    chart1 = ChartRender.barChart()
    chart1 = chart1.barChartRender([''],Datachart,'chart1','true')

    if len(Datatable1.getColumn('cumul_%'))>0:
        Datachartpie.append(100 - float(Datatable1.getColumn('cumul_%')[-1]))
    else:
        Datachartpie.append(100)
    PieChart1 = ChartRender.customPieChart()
    PieChartlabels = list()
    for x in rows:
        PieChartlabels.append(str(x[1]).strip())
    PieChartlabels.append('Others')
    PieChart1 = PieChart1.customPieChartRender('PieChart1',PieChartlabels, Datachartpie)

    # draw chart2
    rows = Datatable2.getAllRow()
    red = 0
    green = 0
    blue = 0
    Datachart = list()
    Datachartpie = list()
    for row in rows:
        label = row[0]+'->'+row[1]
        data = list()
        data.append(row[2])
        Datachartpie.append(row[3])
        if red < 250:
            red += 50
        else:
            if green < 250:
                green += 50
            else:
                if blue < 250:
                    blue += 50
        color = '"rgba({red}, {green}, {blue}, 1)"'
        color = color.format(red=red, green=green, blue=blue)
        dataset = ChartRender.dataSet(color,data, '"'+ label + '"')
        Datachart.append(dataset)
    chart2 = ChartRender.barChart()
    chart2 = chart2.barChartRender([''],Datachart,'chart2','true')

    if len(Datatable2.getColumn('cumul_%'))>0:
        Datachartpie.append(100 - float(Datatable2.getColumn('cumul_%')[-1]))
    else:
        Datachartpie.append(100)
    PieChart2 = ChartRender.customPieChart()
    PieChartlabels = list()
    for x in rows:
        PieChartlabels.append(str(x[0]).strip())
    PieChartlabels.append('Others')
    PieChart2 = PieChart2.customPieChartRender('PieChart2',PieChartlabels, Datachartpie)

    return render_template('multipathIP.html',
    table=Datatable.Table.values.tolist(), Datatable1=Datatable1, Datatable2=Datatable2,
    startdate=datetime.strptime(startdate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'), 
    enddate=datetime.strptime(enddate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'),
    _startdate=datetime.strptime(_startdate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'),
    _enddate=datetime.strptime(_enddate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'),
    counts=_counts, protocol=_protocol, sip=_sip,dip=_dip,num=_num, protocols=protocols, zips=zip(protocols,_check), allproto=allproto,
    chart1=chart1, chart2=chart2, PieChart1=PieChart1, PieChart2=PieChart2
    )
@app.route('/multipathstatistic', methods=['POST', 'GET'])
def multipathstatistic(): 
    global startdate
    global enddate
    _startdate = startdate
    _enddate = enddate 
    _counts =10 
    
    if 'startdate' in request.form:
        _startdate = datetime.strptime(request.form['startdate'] ,'%Y-%m-%dT%H:%M:%S').strftime('%Y/%m/%dT%H:%M:%S')
    if 'enddate' in request.form:
        _enddate = datetime.strptime(request.form['enddate'] ,'%Y-%m-%dT%H:%M:%S').strftime('%Y/%m/%dT%H:%M:%S')
    if 'counts' in request.form:
        _counts = int(request.form['counts'])
    Datacommand = '''rm in_month.rw;rwfilter --start={_startdate} --end={_enddate} --type=in,inweb --protocol=0- --pass=stdout --pass=in_month.rw | rwstats --field=sip,sport --value=flows --count {_counts} --no-columns >multistatistic.txt'''
    Datacommand = Datacommand.format(_startdate=_startdate,_enddate=_enddate,_counts=_counts)
    Datatable = TableFromCommand.TableFromCommand(Datacommand,'multistatistic.txt')
    Datatable = Datatable.execute()
    rows = Datatable.getAllRow()
    chart = ChartRender.barChart()
    red = 0
    green = 0
    blue = 0
    Datachart = list()
    Datachartpie = list()
    for row in rows:
        label = row[0] + '-' + str(row[1])
        data = list()
        data.append(row[2])
        Datachartpie.append(row[3])
        if red < 250:
            red += 50
        else:
            if green < 250:
                green += 50
            else:
                if blue < 250:
                    blue += 50
        color = '"rgba({red}, {green}, {blue}, 1)"'
        color = color.format(red=red, green=green, blue=blue)
        dataset = ChartRender.dataSet(color,data, '"'+ label + '"')
        Datachart.append(dataset)
    chart = ChartRender.barChart()
    chart = chart.barChartRender([''],Datachart,'chartstatistic','true')

    if len(Datatable.getColumn('cumul_%'))>0:
        Datachartpie.append(100 - float(Datatable.getColumn('cumul_%')[-1]))
    else:
        Datachartpie.append(100)
    PieChart = ChartRender.customPieChart()
    PieChartlabels = list()
    for x in rows:
        PieChartlabels.append(str(x[0]).strip() +'-' + str(x[1]).strip())
    PieChartlabels.append('Others')
    PieChart = PieChart.customPieChartRender('PieChart',PieChartlabels, Datachartpie)


    return render_template('multipathStatistic.html',
    Datatable=Datatable,
    startdate=datetime.strptime(startdate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'), 
    enddate=datetime.strptime(enddate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'),
    _startdate=datetime.strptime(_startdate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'),
    _enddate=datetime.strptime(_enddate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'),
    counts=_counts, chart=chart, PieChart = PieChart
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
        _startdate = datetime.strptime(request.form['startdate'] ,'%Y-%m-%dT%H:%M:%S').strftime('%Y/%m/%dT%H:%M:%S')
    if 'enddate' in request.form:
        _enddate = datetime.strptime(request.form['enddate'] ,'%Y-%m-%dT%H:%M:%S').strftime('%Y/%m/%dT%H:%M:%S')
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
    # data command for table
    Datacommand0 = '''rwcut incoming-server.raw --fields=1-4,sensor,proto,flag,stime,etime --num-recs={_counts} --no-columns>incoming-server.txt'''
    Datacommand1 = '''rwcut incoming-client.raw --fields=1-4,sensor,proto,flag,stime,etime --num-recs={_counts} --no-columns>incoming-client.txt'''
    Datacommand2 = '''rwcut outgoing-server.raw --fields=1-4,sensor,proto,flag,stime,etime --num-recs={_counts} --no-columns>outgoing-server.txt'''
    Datacommand3 = '''rwcut outgoing-client.raw --fields=1-4,sensor,proto,flag,stime,etime --num-recs={_counts} --no-columns>outgoing-client.txt'''
    Datacommand4 = '''rwcut leftover.raw --fields=1-4,sensor,proto,flag,stime,etime --num-recs={_counts} --no-columns>leftover.txt'''
    Datacommand5 = '''rwcut lowpacket.rw --fields=1-4,sensor,proto,flag,stime,etime --num-recs={_counts} --no-columns>lowpacket.txt'''
    Datacommand6 = '''rwcut synonly.rw --fields=1-4,sensor,proto,flag,stime,etime --num-recs={_counts} --no-columns>synonly.txt'''
    Datacommand7 = '''rwcut reset.rw --fields=1-4,sensor,proto,flag,stime,etime --num-recs={_counts} --no-columns>reset.txt'''

    Datacommand0 = Datacommand0.format(_counts=_counts)
    Datacommand1 = Datacommand1.format(_counts=_counts)
    Datacommand2 = Datacommand2.format(_counts=_counts)
    Datacommand3 = Datacommand3.format(_counts=_counts)
    Datacommand4 = Datacommand4.format(_counts=_counts)
    Datacommand5 = Datacommand5.format(_counts=_counts)
    Datacommand6 = Datacommand6.format(_counts=_counts)
    Datacommand7 = Datacommand7.format(_counts=_counts)
    # data command for chart
    

    Datacommandchart1 = '''rwstats --fields=dip --values=flows --no-columns incoming-server.raw --count={_counts}>chartTCP1.txt'''
    Datacommandchart2 = '''rwstats --fields=dip --values=flows --no-columns incoming-client.raw --count={_counts}>chartTCP2.txt'''
    Datacommandchart3 = '''rwstats --fields=sip --values=flows --no-columns outgoing-server.raw --count={_counts}>chartTCP3.txt'''
    Datacommandchart4 = '''rwstats --fields=sip --values=flows --no-columns outgoing-client.raw --count={_counts}>chartTCP4.txt'''
    Datacommandchart5 = '''rwstats --fields=sip --values=flows --no-columns leftover.raw --count={_counts}>chartTCP5.txt'''
    Datacommandchart6 = '''rwstats --fields=sip --values=flows --no-columns lowpacket.rw --count={_counts}>chartTCP6.txt'''
    Datacommandchart7 = '''rwstats --fields=sip --values=flows --no-columns synonly.rw --count={_counts}>chartTCP7.txt'''
    Datacommandchart8 = '''rwstats --fields=sip --values=flows --no-columns reset.rw --count={_counts}>chartTCP8.txt'''
    
    Datacommandchart1 = Datacommandchart1.format(_counts=_counts)
    Datacommandchart2 = Datacommandchart2.format(_counts=_counts)
    Datacommandchart3 = Datacommandchart3.format(_counts=_counts)
    Datacommandchart4 = Datacommandchart4.format(_counts=_counts)
    Datacommandchart5 = Datacommandchart5.format(_counts=_counts)
    Datacommandchart6 = Datacommandchart6.format(_counts=_counts)
    Datacommandchart7 = Datacommandchart7.format(_counts=_counts)
    Datacommandchart8 = Datacommandchart8.format(_counts=_counts)

    # exec command
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

    Datatablechart1 = TableFromCommand.TableFromCommand(Datacommandchart1,'chartTCP1.txt')
    Datatablechart1 = Datatablechart1.execute()
    Datatablechart2 = TableFromCommand.TableFromCommand(Datacommandchart2,'chartTCP2.txt')
    Datatablechart2 = Datatablechart2.execute()
    Datatablechart3 = TableFromCommand.TableFromCommand(Datacommandchart3,'chartTCP3.txt')
    Datatablechart3 = Datatablechart3.execute()
    Datatablechart4 = TableFromCommand.TableFromCommand(Datacommandchart4,'chartTCP4.txt')
    Datatablechart4 = Datatablechart4.execute()
    Datatablechart5 = TableFromCommand.TableFromCommand(Datacommandchart5,'chartTCP5.txt')
    Datatablechart5 = Datatablechart5.execute()
    Datatablechart6 = TableFromCommand.TableFromCommand(Datacommandchart6,'chartTCP6.txt')
    Datatablechart6 = Datatablechart6.execute()
    Datatablechart7 = TableFromCommand.TableFromCommand(Datacommandchart7,'chartTCP7.txt')
    Datatablechart7 = Datatablechart7.execute()
    Datatablechart8 = TableFromCommand.TableFromCommand(Datacommandchart8,'chartTCP8.txt')
    Datatablechart8 = Datatablechart8.execute()
    
    # draw chart1
    rows = Datatablechart1.getAllRow()
    red = 0
    green = 0
    blue = 0
    Datachart = list()
    Datachartpie = list()
    for row in rows:
        label = row[0]
        data = list()
        data.append(row[1])
        Datachartpie.append(row[2])
        if red < 250:
            red += 50
        else:
            if green < 250:
                green += 50
            else:
                if blue < 250:
                    blue += 50
        color = '"rgba({red}, {green}, {blue}, 1)"'
        color = color.format(red=red, green=green, blue=blue)
        dataset = ChartRender.dataSet(color,data, '"'+ label + '"')
        Datachart.append(dataset)
    chart1 = ChartRender.barChart()
    chart1 = chart1.barChartRender(['Dest-IP'],Datachart,'chart1','true')

    if len(Datatablechart1.getColumn('cumul_%'))>0:
        Datachartpie.append(100 - float(Datatablechart1.getColumn('cumul_%')[-1]))
    else:
        Datachartpie.append(100)
    PieChart1 = ChartRender.customPieChart()
    PieChartlabels = list()
    for x in rows:
        PieChartlabels.append(str(x[0]).strip())
    PieChartlabels.append('Others')
    PieChart1 = PieChart1.customPieChartRender('PieChart1',PieChartlabels, Datachartpie)

    # draw chart2
    rows = Datatablechart2.getAllRow()
    red = 0
    green = 0
    blue = 0
    Datachart = list()
    Datachartpie = list()
    for row in rows:
        label = row[0]
        data = list()
        data.append(row[1])
        Datachartpie.append(row[2])
        if red < 250:
            red += 50
        else:
            if green < 250:
                green += 50
            else:
                if blue < 250:
                    blue += 50
        color = '"rgba({red}, {green}, {blue}, 1)"'
        color = color.format(red=red, green=green, blue=blue)
        dataset = ChartRender.dataSet(color,data, '"'+ label + '"')
        Datachart.append(dataset)
    chart2 = ChartRender.barChart()
    chart2 = chart2.barChartRender(['Dest-IP'],Datachart,'chart2','true')

    if len(Datatablechart2.getColumn('cumul_%'))>0:
        Datachartpie.append(100 - float(Datatablechart2.getColumn('cumul_%')[-1]))
    else:
        Datachartpie.append(100)
    PieChart2 = ChartRender.customPieChart()
    PieChartlabels = list()
    for x in rows:
        PieChartlabels.append(str(x[0]).strip())
    PieChartlabels.append('Others')
    PieChart2 = PieChart2.customPieChartRender('PieChart2',PieChartlabels, Datachartpie)

    # draw chart3
    rows = Datatablechart3.getAllRow()
    red = 0
    green = 0
    blue = 0
    Datachart = list()
    Datachartpie = list()
    for row in rows:
        label = row[0]
        data = list()
        data.append(row[1])
        Datachartpie.append(row[2])
        if red < 250:
            red += 50
        else:
            if green < 250:
                green += 50
            else:
                if blue < 250:
                    blue += 50
        color = '"rgba({red}, {green}, {blue}, 1)"'
        color = color.format(red=red, green=green, blue=blue)
        dataset = ChartRender.dataSet(color,data, '"'+ label + '"')
        Datachart.append(dataset)
    chart3 = ChartRender.barChart()
    chart3 = chart3.barChartRender(['Dest-IP'],Datachart,'chart3','true')

    if len(Datatablechart3.getColumn('cumul_%'))>0:
        Datachartpie.append(100 - float(Datatablechart3.getColumn('cumul_%')[-1]))
    else:
        Datachartpie.append(100)
    PieChart3 = ChartRender.customPieChart()
    PieChartlabels = list()
    for x in rows:
        PieChartlabels.append(str(x[0]).strip())
    PieChartlabels.append('Others')
    PieChart3 = PieChart3.customPieChartRender('PieChart3',PieChartlabels, Datachartpie)

    # draw chart4
    rows = Datatablechart4.getAllRow()
    red = 0
    green = 0
    blue = 0
    Datachart = list()
    Datachartpie = list()
    for row in rows:
        label = row[0]
        data = list()
        data.append(row[1])
        Datachartpie.append(row[2])
        if red < 250:
            red += 50
        else:
            if green < 250:
                green += 50
            else:
                if blue < 250:
                    blue += 50
        color = '"rgba({red}, {green}, {blue}, 1)"'
        color = color.format(red=red, green=green, blue=blue)
        dataset = ChartRender.dataSet(color,data, '"'+ label + '"')
        Datachart.append(dataset)
    chart4 = ChartRender.barChart()
    chart4 = chart4.barChartRender(['Dest-IP'],Datachart,'chart4','true')

    if len(Datatablechart4.getColumn('cumul_%'))>0:
        Datachartpie.append(100 - float(Datatablechart4.getColumn('cumul_%')[-1]))
    else:
        Datachartpie.append(100)
    PieChart4 = ChartRender.customPieChart()
    PieChartlabels = list()
    for x in rows:
        PieChartlabels.append(str(x[0]).strip())
    PieChartlabels.append('Others')
    PieChart4 = PieChart4.customPieChartRender('PieChart4',PieChartlabels, Datachartpie)

    # draw chart5
    rows = Datatablechart5.getAllRow()
    red = 0
    green = 0
    blue = 0
    Datachart = list()
    Datachartpie = list()
    for row in rows:
        label = row[0]
        data = list()
        data.append(row[1])
        Datachartpie.append(row[2])
        if red < 250:
            red += 50
        else:
            if green < 250:
                green += 50
            else:
                if blue < 250:
                    blue += 50
        color = '"rgba({red}, {green}, {blue}, 1)"'
        color = color.format(red=red, green=green, blue=blue)
        dataset = ChartRender.dataSet(color,data, '"'+ label + '"')
        Datachart.append(dataset)
    chart5 = ChartRender.barChart()
    chart5 = chart5.barChartRender(['Dest-IP'],Datachart,'chart5','true')

    if len(Datatablechart5.getColumn('cumul_%'))>0:
        Datachartpie.append(100 - float(Datatablechart5.getColumn('cumul_%')[-1]))
    else:
        Datachartpie.append(100)
    PieChart5 = ChartRender.customPieChart()
    PieChartlabels = list()
    for x in rows:
        PieChartlabels.append(str(x[0]).strip())
    PieChartlabels.append('Others')
    PieChart5 = PieChart5.customPieChartRender('PieChart5',PieChartlabels, Datachartpie)

    # draw chart6
    rows = Datatablechart6.getAllRow()
    red = 0
    green = 0
    blue = 0
    Datachart = list()
    Datachartpie = list()
    for row in rows:
        label = row[0]
        data = list()
        data.append(row[1])
        Datachartpie.append(row[2])
        if red < 250:
            red += 50
        else:
            if green < 250:
                green += 50
            else:
                if blue < 250:
                    blue += 50
        color = '"rgba({red}, {green}, {blue}, 1)"'
        color = color.format(red=red, green=green, blue=blue)
        dataset = ChartRender.dataSet(color,data, '"'+ label + '"')
        Datachart.append(dataset)
    chart6 = ChartRender.barChart()
    chart6 = chart6.barChartRender(['Dest-IP'],Datachart,'chart6','true')

    if len(Datatablechart6.getColumn('cumul_%'))>0:
        Datachartpie.append(100 - float(Datatablechart6.getColumn('cumul_%')[-1]))
    else:
        Datachartpie.append(100)
    PieChart6 = ChartRender.customPieChart()
    PieChartlabels = list()
    for x in rows:
        PieChartlabels.append(str(x[0]).strip())
    PieChartlabels.append('Others')
    PieChart6 = PieChart6.customPieChartRender('PieChart6',PieChartlabels, Datachartpie)

    # draw chart7
    rows = Datatablechart7.getAllRow()
    red = 0
    green = 0
    blue = 0
    Datachart = list()
    Datachartpie = list()
    for row in rows:
        label = row[0]
        data = list()
        data.append(row[1])
        Datachartpie.append(row[2])
        if red < 250:
            red += 50
        else:
            if green < 250:
                green += 50
            else:
                if blue < 250:
                    blue += 50
        color = '"rgba({red}, {green}, {blue}, 1)"'
        color = color.format(red=red, green=green, blue=blue)
        dataset = ChartRender.dataSet(color,data, '"'+ label + '"')
        Datachart.append(dataset)
    chart7 = ChartRender.barChart()
    chart7 = chart7.barChartRender(['Dest-IP'],Datachart,'chart7','true')

    if len(Datatablechart7.getColumn('cumul_%'))>0:
        Datachartpie.append(100 - float(Datatablechart7.getColumn('cumul_%')[-1]))
    else:
        Datachartpie.append(100)
    PieChart7 = ChartRender.customPieChart()
    PieChartlabels = list()
    for x in rows:
        PieChartlabels.append(str(x[0]).strip())
    PieChartlabels.append('Others')
    PieChart7 = PieChart7.customPieChartRender('PieChart7',PieChartlabels, Datachartpie)

    # draw chart8
    rows = Datatablechart8.getAllRow()
    red = 0
    green = 0
    blue = 0
    Datachart = list()
    Datachartpie = list()
    for row in rows:
        label = row[0]
        data = list()
        data.append(row[1])
        Datachartpie.append(row[2])
        if red < 250:
            red += 50
        else:
            if green < 250:
                green += 50
            else:
                if blue < 250:
                    blue += 50
        color = '"rgba({red}, {green}, {blue}, 1)"'
        color = color.format(red=red, green=green, blue=blue)
        dataset = ChartRender.dataSet(color,data, '"'+ label + '"')
        Datachart.append(dataset)
    chart8 = ChartRender.barChart()
    chart8 = chart8.barChartRender(['Dest-IP'],Datachart,'chart8','true')

    if len(Datatablechart8.getColumn('cumul_%'))>0:
        Datachartpie.append(100 - float(Datatablechart8.getColumn('cumul_%')[-1]))
    else:
        Datachartpie.append(100)
    PieChart8 = ChartRender.customPieChart()
    PieChartlabels = list()
    for x in rows:
        PieChartlabels.append(str(x[0]).strip())
    PieChartlabels.append('Others')
    PieChart8 = PieChart8.customPieChartRender('PieChart8',PieChartlabels, Datachartpie)

    return render_template('multipathTCP.html',
    Datatable0=Datatable0,Datatable1=Datatable1,Datatable2=Datatable2,Datatable3=Datatable3,Datatable4=Datatable4,
    Datatable5=Datatable5,Datatable6=Datatable6,Datatable7=Datatable7,
    startdate=datetime.strptime(startdate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'), 
    enddate=datetime.strptime(enddate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'),
    _startdate=datetime.strptime(_startdate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'),
    _enddate=datetime.strptime(_enddate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'),
    counts=_counts,sensor=_sensor, protocols=protocols, 
    chart1=chart1, PieChart1=PieChart1, chart2=chart2, PieChart2=PieChart2, 
    chart3=chart3,PieChart3=PieChart3,chart4=chart4, PieChart4=PieChart4,
    chart5=chart5, PieChart5=PieChart5,chart6=chart6, PieChart6=PieChart6,
    chart7=chart7, PieChart7=PieChart7,chart8=chart8, PieChart8=PieChart8
    )
@app.route('/multipathdns', methods=['POST', 'GET'])
def multipathdns(): 
    global startdate
    global enddate
    _startdate = startdate
    _enddate = enddate 
    _counts =10 
    
    if 'startdate' in request.form:
        _startdate = datetime.strptime(request.form['startdate'] ,'%Y-%m-%dT%H:%M:%S').strftime('%Y/%m/%dT%H:%M:%S')
    if 'enddate' in request.form:
        _enddate = datetime.strptime(request.form['enddate'] ,'%Y-%m-%dT%H:%M:%S').strftime('%Y/%m/%dT%H:%M:%S')
    if 'counts' in request.form:
        _counts = int(request.form['counts'])
    # create data command for table
    Command0 = '''rm in_month.rw interest.set;rwfilter --start={_startdate} --end={_enddate} --type=in,inweb --protocol=0- --pass=in_month.rw; rwfilter in_month.rw --protocol=17 --aport=53 --pass=stdout | rwset --sip-file=interest.set'''
    Command0 = Command0.format(_startdate=_startdate,_enddate=_enddate)
    Command1 = '''rm not-dns.rw dns.rw dns-saddr.txt;rwfilter in_month.rw --sipset=interest.set --protocol=17 --pass=stdout | rwfilter stdin --aport=53 --fail=not-dns.rw --pass=stdout --pass=dns.rw | rwuniq --fields=sIP --no-titles  --sort-output --no-columns --output-path=dns-saddr.txt'''
    Command2 = '''rm not-dns-saddr.txt;rwuniq not-dns.rw --fields=sip --no-titles  --sort-output --no-columns --output-path=not-dns-saddr.txt'''
    
    # execute command and creat data
    os.chdir('data')
    os.system(Command0)
    os.system(Command1)
    os.system(Command2)
    os.chdir('..')
    Datacommand = '''rm dns-temp.txt;echo 'sIP|DNS||not DNS|' >dns.txt;join -t '|' dns-saddr.txt not-dns-saddr.txt | sort -t '|' -nrk2,2 | head -{_counts}>dns_temp.txt;cat dns_temp.txt>>dns.txt'''
    Datacommand = Datacommand.format(_counts=_counts)
    Datatable = TableFromCommand.TableFromCommand(Datacommand,'dns.txt')
    Datatable = Datatable.execute()
    # data command for chart
    Datacommandchart1 = '''rwstats dns.rw --fields=sIP --values=records --no-columns --count={_counts}>chart1.txt'''
    Datacommandchart2 = '''rwstats not-dns.rw --fields=sIP --values=records --no-columns --count={_counts}>chart2.txt'''
    Datacommandchart1 = Datacommandchart1.format(_counts=_counts)
    Datacommandchart2 = Datacommandchart2.format(_counts=_counts)
    Datatablechart1 = TableFromCommand.TableFromCommand(Datacommandchart1,'chart1.txt')
    Datatablechart2 = TableFromCommand.TableFromCommand(Datacommandchart2,'chart2.txt')
    Datatablechart1 = Datatablechart1.execute()
    Datatablechart2 = Datatablechart2.execute()

    # draw chart1
    rows = Datatablechart1.getAllRow()
    chart = ChartRender.barChart()
    red = 0
    green = 0
    blue = 0
    Datachart = list()
    Datachartpie = list()
    for row in rows:
        label = row[0]
        data = list()
        data.append(row[1])
        Datachartpie.append(row[2])
        if red < 250:
            red += 50
        else:
            if green < 250:
                green += 50
            else:
                if blue < 250:
                    blue += 50
        color = '"rgba({red}, {green}, {blue}, 1)"'
        color = color.format(red=red, green=green, blue=blue)
        dataset = ChartRender.dataSet(color,data, '"'+ label + '"')
        Datachart.append(dataset)
    chart1 = ChartRender.barChart()
    chart1 = chart.barChartRender(['Sourc-IP'],Datachart,'chart1','true')

    if len(Datatablechart1.getColumn('cumul_%'))>0:
        Datachartpie.append(100 - float(Datatablechart1.getColumn('cumul_%')[-1]))
    else:
        Datachartpie.append(100)
    PieChart1 = ChartRender.customPieChart()
    PieChartlabels = list()
    for x in rows:
        PieChartlabels.append(str(x[0]).strip())
    PieChartlabels.append('Others')
    PieChart1 = PieChart1.customPieChartRender('PieChart1',PieChartlabels, Datachartpie)

    # draw chart2
    rows = Datatablechart2.getAllRow()
    chart = ChartRender.barChart()
    red = 0
    green = 0
    blue = 0
    Datachart = list()
    Datachartpie = list()
    for row in rows:
        label = row[0]
        data = list()
        data.append(row[1])
        Datachartpie.append(row[2])
        if red < 250:
            red += 50
        else:
            if green < 250:
                green += 50
            else:
                if blue < 250:
                    blue += 50
        color = '"rgba({red}, {green}, {blue}, 1)"'
        color = color.format(red=red, green=green, blue=blue)
        dataset = ChartRender.dataSet(color,data, '"'+ label + '"')
        Datachart.append(dataset)
    chart2 = ChartRender.barChart()
    chart2 = chart.barChartRender(['Sourc-IP'],Datachart,'chart2','true')

    if len(Datatablechart2.getColumn('cumul_%'))>0:
        Datachartpie.append(100 - float(Datatablechart2.getColumn('cumul_%')[-1]))
    else:
        Datachartpie.append(100)
    PieChart2 = ChartRender.customPieChart()
    PieChartlabels = list()
    for x in rows:
        PieChartlabels.append(str(x[0]).strip())
    PieChartlabels.append('Others')
    PieChart2 = PieChart2.customPieChartRender('PieChart2',PieChartlabels, Datachartpie)

    return render_template('multipathDNS.html',
    Datatable=Datatable,
    startdate=datetime.strptime(startdate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'), 
    enddate=datetime.strptime(enddate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'),
    _startdate=datetime.strptime(_startdate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'),
    _enddate=datetime.strptime(_enddate,'%Y/%m/%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S'),
    counts=_counts, chart1=chart1,PieChart1=PieChart1, chart2=chart2,PieChart2=PieChart2
    )
if __name__ == '__main__':
    app.run(debug = True, host='0.0.0.0', port='2222')
   
