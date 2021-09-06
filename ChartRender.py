
class dataSet():
    '''a dataset of datasets'''
    def __init__(self, color, datalist, label):
        self.color = color
        self.datalist = datalist
        self.label = label

class barChart:
    '''bar chart class'''
    def __init__(self):
        self.barChart_raw = '''// ------------------------------------------------------- //
        // Bar Chart
        // ------------------------------------------------------ //
        var barChart{id} = new Chart($('#{id}'), {{
            type: 'bar',
            options: {{
                scales: {{
                    xAxes: [{{
                        display: false,
                        gridLines: {{
                            color: '#eee'
                        }}
                    }}],
                    yAxes: [{{
                        display: {yAxes},
                        ticks: {{
                            beginAtZero: true
                        }},
                        gridLines: {{
                            display: false
                        }}
                    }}]
                }},
            }},
            data: {{
                labels: {labels},
                datasets: [
                    {datasets}
                ]
            }}
        }});'''

        self.barChart_datasets = '''
                        {{
                            
                            label: {label},
                            backgroundColor: [
                                {color}
                            ],
                            hoverBackgroundColor: [
                                {color}
                            ],
                            borderColor: [
                                {color}
                            ],
                            borderWidth: 1,
                            data: {data},
                        }}'''


    def barChartRender(self, labels, data, id, yAxes):
        datasets = ''
        for set in data: 
            color = ''
            for x in set.datalist:
                color = color + set.color
                if set.datalist.index(x) != len(set.datalist)-1:
                    color = color + ','
            datasets = datasets + (self.barChart_datasets).format(label = set.label, color = color,data = set.datalist)
            if set != data[-1]:
                datasets = datasets + ','
        finalChart = self.barChart_raw.format(id = id, labels = labels, datasets = datasets, yAxes = yAxes)
        return finalChart

class customPieChart():
    '''custom pie chart render class'''
    def __init__(self):
        self.customPieChart_raw = '''
            var {id} = new Chart($('#{id}'), {{
            type: 'pie',
            options: {{
                legend: {{
                    display: true,
                    position: "left"
                }}
            }},
            data: {{
                labels: {labels},
                datasets: [
                    {{
                        data: {data},
                        borderWidth: 0,
                        backgroundColor: {color},
                        hoverBackgroundColor: {color}
                    }}
                    ]
                }}
            }});'''
        self.colorList = ['#F2F5A9', '#FF4000','#0000FF','#81F781','#F5A9BC','#819FF7','#F7FE2E','#E0F8F7','#FFFFFF','#FF0000','#00FF00','#0000FF','#FFFF00','#00FFFF','#FF00FF','#C0C0C0','#808080','#800000','#808000','#008000','#800080','#008080','#000080']
    
    def customPieChartRender(self, id, labels, data):
        chart = self.customPieChart_raw.format(id = id, labels = labels, data = data, color = self.colorList[0:len(data)-1])
        return chart

'''
if __name__ == "__main__":
    barchart = barChart()
    dataset1 = dataSet('"rgba(134, 77, 217, 0.57)"', [1,2],'"set1"')
    dataset2 = dataSet('"rgba(134, 77, 217, 1)"', [3,2],'"set2"')
    data = [dataset1,dataset2]
    chart = barchart.barChartRender(["req","Qwerwe"], data, "x")
    print(chart)'''