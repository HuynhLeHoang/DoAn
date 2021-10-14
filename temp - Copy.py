from typing_extensions import final
from werkzeug.datastructures import cache_property
import ChartRender

def test():
    dt1 = ChartRender.dataSet('"rgba(255, 98, 0, 1)"', [1,2], 'dt1')
    dt2 = ChartRender.dataSet('"rgba(255, 98, 0, 1)"', [5,6], 'dt2')
    dts = [dt1,dt2]
    chart = ChartRender.barChart()
    finalchart = chart.barChartRender(['Thang 1', 'Thang 2'], dts, 'barchartmonth', 'true')
    print(finalchart)

if __name__ == "__main__":
    test()
    print('1')