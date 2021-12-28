import datetime
class ServerAttackDector():

    #Constructor where path is the file path csv
    def __init__(self, path):
        try:
            self.path = path
            self.theFile = self.readFile()
        except OSError:
            print("File cannot be found/open. Path set to None")
            self.path = None
            self.theFile = None
    
    #Returns the first occurence of a potential ddos attack
    def detect(self):
        filteredList = filter(lambda x: self.lineFilter(x), self.theFile) 
        lastUDP = None
        lastUDPTime = None
        for line in filteredList:
            splitLine = line.split(",")
            thisTime = self.getDateTime(splitLine)
            if lastUDP == None:
                lastUDP = splitLine
                lastUDPTime = thisTime
            else:
                if float(splitLine[1]) < 1:
                    timeDifference = (thisTime - lastUDPTime).total_seconds()
                    if timeDifference < 1:
                        return splitLine[-1], ",".join(splitLine[0:len(splitLine) - 1])
                lastUDP = splitLine
                lastUDPTime = thisTime
        return None, None 

    #Converts a date line to a date_time object
    def getDateTime(self,dateLine):
                    day = dateLine[0]
                    dateObj = datetime.datetime.strptime(day, "%Y-%m-%d %H:%M:%S.%f")
                    return dateObj

    #Reads the file and yields each line
    def readFile(self):
        for index,line in enumerate(open(self.path, "r")):
            yield line + "," + str(index)

    #Keeps lines that are UDP and marked as suspicious
    def lineFilter(self, line):
        if line == None:
            return False
        linePart = line.split(",")
        if "UDP" in linePart[2] and linePart[12] == "suspicious":
            return True
        return False


