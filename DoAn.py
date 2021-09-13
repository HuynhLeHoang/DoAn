
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

if __name__ == '__main__':
    app.run(debug = True, host='0.0.0.0', port='2222')
   
