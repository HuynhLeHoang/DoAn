
def save(startdateFile,enddateFile):
    sfile = open('status.txt','r+')
    sfile.write(startdateFile)
    sfile.write('\n')
    sfile.write(enddateFile)