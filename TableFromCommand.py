import os
import TableFromFile

class TableFromCommand:
    '''A class read data from silk output which is in table format'''
    def __init__(self, command, filename):
        self.command = command
        self.filename = filename

        
        try:
            os.remove('FCCX-silk/' + self.filename)
        except:
            pass

        
    def execute(self):
        os.chdir('FCCX-silk/')
        os.system(self.command)
        os.chdir('..')
        table = TableFromFile.TableFromFile(self.filename, True)

        return table

'''
if __name__== '__main__':
    command = 'rwsiteinfo --fields=sensor,describe-sensor'
    table = TableFromCommand(command)
    print(table.result)
'''