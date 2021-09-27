from numpy.lib.function_base import select
import pandas as pd
import os

from pandas.core.algorithms import isin

class TableFromFile():
    '''Load a table from file'''
    
    def __init__(self, filename, headerExistant=True):
        self.filename = filename
        #remove unconstruct line
        thisfile = open('data/' + filename,'r')
        lines = thisfile.readlines()
        thisfile.close()
        newfile = open('data/' + filename, "w")
        if len(lines)>0:
            if 'INPUT' in lines[0]:
                del lines[0]
                del lines[0]
        for line in lines:
            newfile.write(line)
        newfile.close()
        #done remove.
        self.Table = pd.read_csv('data/' + filename, sep="|", encoding="utf8")
        self.headerExistant = headerExistant
        columns = self.Table.columns.tolist()
        columns = columns[:len(columns)-1]
        self.Table = pd.read_csv('data/' + filename, sep="|", encoding="utf8", usecols=columns)
        
    def getRow(self,index):
        '''get all element from a row'''
        row = self.Table.values.tolist()
        rawrow = row[index]
        returnrow = []
        for element in rawrow:
            if (isinstance(element, str)):
                element = element.strip(' ')
                returnrow.append(element)
            else:
                returnrow.append(element)
        

        return returnrow

    def getAllRow(self):
        '''get all row from table'''
        row = self.Table.values.tolist()
        returnrow = list()
        for x in row:
            returnrow.append(x)
        return returnrow

    def getColumn(self,columnName):
        header = self.getHeader()
        index = header.index(columnName)
        rows = self.Table.values.tolist()
        returncolumn = list()
        for row in rows:
            returncolumn.append(row[index])
        return returncolumn        

    def getHeader(self):
        '''get the headers if exitst'''
        if(type(self.headerExistant)==bool):
            if(self.headerExistant == True):
                rawheader = self.Table.columns.tolist()
                header = []
                for title in rawheader:
                    if (isinstance(title, str)):
                        title = title.replace(' ','')
                        header.append(title)
                    else:
                        header.append(title)
                return header
    
'''
if __name__ == "__main__":
    table = TableFromFile("iptoip.txt",True)
    print("Header of table:" )
    print(table.getHeader())
    print("The first row:")
    print(table.getRow(0))
    print("sTime column:")
    print(table.getColumn("eTime"))
    print("Table:")
    print(table.Table)
'''