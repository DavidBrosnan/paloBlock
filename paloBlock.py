#!/usr/bin/python
import sys
import csv
import urllib
import xml.etree.ElementTree as ET
import logging
import logging.handlers
import os.path


b_url = pa_settings['base_url'] + '/?type=config'+ '&key=' + pa_settings['authkey']

prefix = "Palo Alto API call:"

logger = logging.getLogger('blocklister')
hdlr = logging.handlers.SysLogHandler(address = '/dev/log')
formatter = logging.Formatter('%(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr) 
logger.setLevel(logging.INFO)

idTag = "blocklist"

dynNameReserve = []

verbosity = False
numPrint = 0
current = 0

addrCluster = 200

def addAddress(addrList, tag, tagList):
    #print "In addAddress"
    """ Crafts a URL for an API call to add an address with idTag and an
        additional tag

        Args:
            addList: List of FQDN's to be added as addresses
            tag: tag name (must exist)
            blockList: addresses already on the server

        Returns:
            a string of the full URL for the API call
    """

    global b_url
    global xpath

    global dynNameReserve

    #tagList = getNameList(tag, blockList)

    element = ""

    for fqdn in addrList:
        name = getName(tag, tagList, dynNameReserve)
        dynNameReserve.append(name)
    
        element += '<entry name="' + name + '"><fqdn>' + fqdn + \
        '</fqdn><tag><member>' + idTag + '</member><member>' + tag + \
        '</member></tag></entry>'

    return b_url + '&action=set&xpath=' + xpath + '&element=' + element

def delAddress(name):

    """ Crafts a URL for an API call to delete an Address

        Args:
            name: Name of the Address

        Returns:
            a string of the full URL for the API call

    """

    global b_url
    global xpath

    return b_url + '&action=delete&xpath=' + xpath + '/entry[@name=\'' + name + '\']'

def addTag(name, tag):

    """ Crafts a URL for an API call to add a tag to the target Address

        Args:
            name: Name of the Address
            tag: tag name (must exist)

        Returns:
            a string of the full URL for the API call
    """

    global b_url
    global xpath

    return b_url + '&action=set&xpath=' + xpath + '/entry[@name=\'' + name + '\']/tag' + '&element=<member>' + tag + '</member>'

def removeTag(name, tag):
    
    """ Crafts a URL for an API call to remove a tag from a target Address

        Args:
            name: Name of the Address
            tag: tag name (must exist)

        Returns:
            a string of the full URL for the API call
    """        
    
    global b_url
    global xpath
    
    return b_url + '&action=delete&xpath=' + xpath + '/entry[@name=\'' + name + '\']/tag/member[text()=\'' + tag + '\']'
               

def getDomains(filePath):
    
    """ Creates a list of FQDN as read from the csv file

        Args:
            filePath: file path of the csv

        Returns:
            a list of FQDN names

    """

    fileName = os.path.basename(filePath)
    tag = fileName[:fileName.rfind("."):]

    domains = []

    f = open(filePath, "rb")
    
    reader = csv.reader(f)

    for row in reader:
        domains.append(row[0])

    return domains

def getCurrentDict():  

    """ Creates a dictionary of all the current addresses with idTag as a tag
        
        Args:
            none

        Return:
            Returns a dictionary of the all the current addresses with
            idTag as a tag in the form of { FQDN : [name, [tags]] }
    """
        
    XML = APIcallXML()

    root = ET.fromstring(XML)
    
    totList = {}
    

    for item in root.findall(".//result/entry[@name='vsys1']/address/entry"):
        fqdn = item.find("./fqdn")

        if fqdn is not None:  # Assume all addresses we are interested in have a fqdn
        
            for member in item.findall("./tag/member"):
           
                if fqdn.text not in totList: 
                    totList[fqdn.text] = [item.attrib["name"],[]]

                totList[fqdn.text][1].append(member.text)

    blockList = {}

    for name, info in totList.iteritems():
        if idTag in info[1]:  # if idTag is an owned tag
            blockList[name] = info

    return blockList 

def getNameList(tag, blockList):
    #print "In getNameList"
    """ Gets a list of names related to a tag

        Args:
            tag: name of tag
            blockList: dictionary of addresses currently on the page

        Returns:
            a list of names already in use for the corresponding tag
            blockList will have names not exclusive to the tag
    """

    tagList = []

    for fqdn, info in blockList.iteritems():
        if tag in info[0]:
            tagList.append(info[0])

    return tagList

def getName(tag, tagList, dynNameReserve):
    #print "In getName"
    """ Gets earliest available name for a new address
    
        Args:
            tag: name of tag
            tagList: list returned by getNameList (On the server)
            dynNameReserve: list of names already used for this session

        Returns:
            First available name for a corresponding tag
    """

    start = 0
    index = 0

    if len(dynNameReserve) != 0:
        for i, c in enumerate(dynNameReserve[-1]):
            if c.isdigit():
                index = i
                break
        start = int(dynNameReserve[-1][index::])
        #print start
    

    for i in xrange(start, 1000000):
        num = '{0:06}'.format(i)
        if (tag + num) not in tagList and (tag + num) not in dynNameReserve:
            return tag + num
"""
    for i in xrange(0, start):
        num = '{0:04}'.format(i)
        if (tag + num) not in tagList and (tag + num) not in dynNameReserve:
            return tag + num

"""
    

def APIhandle(op, fqdn, address, tag):
    
    """ Handles information related to API call and logging
        
        Args:
            
             op:
                "remTag": Remove tag from this name
                "AddTag": Add tag to this name
                "addAddr": Add this Address to Palo Alto with these attributes
                "delAddr": Delete this addresss from the server 
            
            fqdn: Fully Qualified Domain Name of the address
            address: The address name for Palo Alto
            tag: What file(s) the FQDN is associated with
           
        Returns:
           Boolean, whether the API call successfully altered Palo Alto or not
            
           
    """

    global prefix
    global verbosity
    global current
    global numPrint

    flag = True

    log = 'Name: ' + address + ' -- FQDN: ' + fqdn + ' -- tag: ' + tag

    if op == "remTag":
        success = prefix + " Removed tag -- " + log
        error = prefix + " Failed tag removal -- " + log

        if not APIcall(removeTag(address,tag), success, error):
            flag = False
   
    elif op == "addTag":
        success = prefix + " Added Tag -- " + log
        error = prefix + " Failed adding tag -- " + log

        if not APIcall(addTag(address, tag), success, error):
            flag = False

    elif op == "delAddr":
        success = prefix + " Successfully deleted address -- " + log
        error = prefix + " Failed to delete address -- " + log

        if not APIcall(delAddress(address), success, error):
            flag = False

    if verbosity:
        current += 1

        if current == numPrint:
            current = 0
            print str(numPrint) + " API calls made"

    return flag

def APIaddAddrHandle(addrList, tag, blockList):
    #print "In APIaddAddrHandle"
    """
        Args:
            addrList: list of FQDN's to be added
            tag: tag to associate with the added address
            blockList: current addresses on server
        
        Returns:
            Boolean, whether API call succeeded and made changes or not

    """
    global verbosity
    global numPrint
    global current
    global prefix
    global addrCluster

    current = 0  # No address API commands have been issued
    flag = True

    tagList = getNameList(tag, blockList)

    log = "Address Count: " + str(len(addrList)) + " -- Tag: " + tag

    success = prefix + " Successfully inserted address list -- " + log
    error = prefix + " Failed to insert address list -- " + log

    parentList = []

    index = 0

    while len(addrList) > addrCluster:
        #print "Addrlist len: " + str(len(addrList))
        parentList.append([])
        for i in range(0,addrCluster):
            parentList[index].append(addrList.pop(0))

        index += 1

    parentList.append(addrList)

    #print len(parentList)

    total = 0

    totAddress = str((addrCluster * (len(parentList) - 1)) + len(addrList))

    if verbosity:
        print "Adding Addresses(" + totAddress + ")"

    for sublist in parentList:
        total += len(sublist)
        if not APIcall(addAddress(sublist, tag, tagList), success, error):
            flag = False
    
        if (verbosity):
            current += 1
    
            if current == numPrint or len(sublist) == len(addrList):
                current = 0
                print str(total) + "/" + totAddress


    return flag
    
def APIcall(url, success, error):
    #print "API call..."
    """ Makes a request to the API
    
        Args:
            url: full URL of the request
            success: What to print to logger if the API call succeeds

        Returns:
            Boolean, whether the API call succeeded and made changes or not
    """

    f = urllib.urlopen(url)
    #return True
    return APIsuccess(url, f.read(), success, error)

def APIsuccess(url, xmlResponse, success, error):
    #print "API success..."
    """ Determines the success of the API call and directly handles logging
        information
        
        Args:
            xmlResponse: The XML response from the APIcall
            success: the success message to log

        Returns:
            Boolean, whether or not the call was successful

    """
    global prefix

    status = False

    root = ET.fromstring(xmlResponse)

    messageField = root.find(".//msg")
    
    if messageField is not None:
        message = messageField.text

        if message is None:  # Message sometimes contained in <msg><line></line></msg>
            message = root.find(".//line").text
        
        if root.attrib["status"] == "success" and root.attrib["code"] == "20" and message == "command succeeded":
            logger.info(success)
            status = True
            #print "API call worked! Print to log as INFO"

        elif message is not None:
            #print "API call failed! here's why! Print to log as ERROR"
            logger.error(error + "\n" +  message + '\n' + url)
        
        else:
            #print "Unknown error, dumping XML..."
            logger.error(error + "\nUnknown Error: \n" + url + '\n' + xmlResponse)

    else:
        
        #print "No message tag present, dumping XML..."
        logger.error(error + "\nUnknown Error: \n" + url + '\n' + xmlResponse)
 
    return status

def APIcallXML():

    """ Obtains XML a portion of the current state of Palo Alto
        in order to parse out the Addresses 

        Args:
            None

        Returns:
            If the API call is successful it returns the result
    """
    
    global prefix

    url = pa_settings['base_url'] + "/?type=config&action=get&key=%s" % \
    pa_settings['authkey'] + \
    "&xpath=/config/devices/entry/vsys/entry[@name='vsys1']"
    
    f = urllib.urlopen(url)
    
    XML = f.read()
    
    root = ET.fromstring(XML)
    resultField = root.find(".//result") 
    
    if len(resultField) != 0:
        logger.info(prefix + " Obtained XML view for address parsing")

    else:
        logger.error(prefix + " Failed to obtain XML view for address parsing -- Exiting now\n" + url)
        sys.exit(0)

    return XML    

def update(filePath):
    #print "In update..."
    """ Handles the adding of addresses, adding of tags, and removal of
    addresses

        Args:
            filePath: file path of the csv file to extract and update the server

        Returns:
            Boolean, Whether the entire operation was successful
        
    """
    global verbosity

    blockList = getCurrentDict()
    csv = getDomains(filePath)
    
    fileName = os.path.basename(filePath) #/path/to/file.csv --> file.csv   
    tag = fileName[:fileName.rfind("."):] #file.csv --> file
    
    addList = []
    
    succeeded = True

    if verbosity:
        print "Adding Tags, Removing Tags, Deleting Addresses..."

    for fqdn, info in blockList.iteritems():
    
        if fqdn not in csv and tag in blockList[fqdn][1]: 
            # The fqdn exists in the blockList(on PA) but not 
            # in the .csv and they are already associated by tag
            # Remove tag from fqdn
            if not APIhandle("remTag", fqdn, blockList[fqdn][0], tag):
                succeeded = False
   
    for fqdn in csv:
    
        if fqdn not in blockList: #if its in the csv but not the idTag
            # The fqdn exists in the .csv but not on Palo Alto
            # Append it to a list of fqdn's to be added
            addList.append(fqdn)
    
        elif tag not in blockList[fqdn][1]:
            # The fqdn exists in the .csv and on Palo Alto but
            # does not have the tag associated with it
            # Add the tag to fqdn
            if not APIhandle("addTag", fqdn, blockList[fqdn][0], tag):
                succeeded = False

    if len(addList) != 0:  # If there are addresses to be added to Palo Alto
            if not APIaddAddrHandle(addList, tag, blockList):
                succeeded = False

    return succeeded
       
def delete():
   """ Deletes addresses on the server with the idTag as its only tag

        Args:
            None

        Returns:
            Boolean, Whether the entire operation succeeded or not
    
   """

   global verbosity

   if verbosity:
       print "Deleting addresses..."

   succeeded = True

   blockList = getCurrentDict()
   for fqdn, info in blockList.iteritems():
       
       if len(blockList[fqdn][1]) == 1 and idTag in blockList[fqdn][1]:
           if not APIhandle("delAddr", fqdn, blockList[fqdn][0], idTag):
               succeeded = False
   return succeeded

def purge(tag):

    """ Deletes addresses with the idTag and tag parameter, or removes tag if
    other tags exist

        Args:
            tag: tag for deletion

        Returns:
            Boolean, Whether the entire operation succeeded or not
    """

    succeeded = True
    noTags = True
    blockList = getCurrentDict()

    global verbosity
    if verbosity:
        print "Purging Addresses..."

    for fqdn, info in blockList.iteritems():

        if idTag in blockList[fqdn][1] and tag in blockList[fqdn][1]:

            if idTag == tag:
                sys.stderr.write("Cannot purge idTag\n")
                sys.exit(0)

            elif len(blockList[fqdn][1]) == 2:
                noTags = False
                if not APIhandle("delAddr", fqdn, blockList[fqdn][0], tag):
                    succeeded = False
    
            elif len(blockList[fqdn][1]) > 2:
                noTags = False
                if not APIhandle("remTag", fqdn, blockList[fqdn][0], tag):
                    succeeded = False
    
            else:
                 pass
    
    if noTags:
        sys.stderr.write("No candidates match for deletion\n")


    return succeeded

def error():
    return "API calls failed -- Please check error log"

def help(std):
   
    """ Prints help screen
        
        Args:
            std: True - stdout False - stderr

        Returns:
            None
    """
   
    
    out = ''

    if std:
        out = sys.stdout.write
    else:
        out = sys.stderr.write 

    out("paloBlock v1.1\n")
    out("Automated Dynamic Address Group handling for FQDN blockList\n")
    out("implemented in the PaloAlto firewall XML API with tag-based association\n")
    out("usage: paloBlock [options] [command] {file}\n\n")
    out("COMMANDS:\n\n")
    out("    update [/path/to/file.csv]\n\n")
    out("          Updates firewall Addresses to reflect information in file\n")
    out("          Automated tag addition/removal and address creation\n")
    out("          File name used for tag and address name prefix\n")
    out("          (**Tag must already exist on server**)\n\n")
    out("    delete\n\n ")
    out("          Delete all addresses on server associated\n")
    out("          with the idTag but no other tag\n\n")
    out("    purge [tag]\n\n")
    out("          Delete all addresses associated with only\n")
    out("          the idTag and [tag], other addresses with\n")
    out("          [tag] have it removed\n\n")
    out("    help\n\n")
    out("          Print this menu\n\n")
    out("OPTIONS:\n\n")
    out("    -v, --verbose  [num]\n\n")
    out("           Number of API calls made before printing\n")
    out("           progress to stdout\n")
    out("           If num is greater than API calls made\n")
    out("           in a cluster output may not print to screen\n\n")

if __name__=='__main__': 

   
    if "-v" in sys.argv or "--verbose" in sys.argv:
        try:
            index = sys.argv.index("-v")
        except Exception as e:
            index = sys.argv.index("--verbose")

        if len(sys.argv) > (index + 1):
            num = sys.argv[index + 1]
            if num.isdigit():
                if int(num) < 0:
                    help(False)
                    sys.exit(0)
                else:
                    verbosity = True
                    numPrint = int(num) 
                    sys.argv.pop(index)  # remove -v
                    sys.argv.pop(index)  # remove the number
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "update":
            if len(sys.argv) == 3:
               if not update(sys.argv[2]):
                   sys.stderr.write(error() + '\n')
            
            else:
                sys.stderr.write("Please include file name\n")
    
        elif sys.argv[1] == "delete" and len(sys.argv) == 2:
            if not delete():
                sys.stderr.write(error() + '\n')
        
        elif sys.argv[1] == "purge":
            if len(sys.argv) == 3:
                if not purge(sys.argv[2]):
                    sys.stderr.write(error() + '\n')
            else:
                sys.stderr.write("Please include tag\n")

        elif sys.argv[1] == "help" and len(sys.argv) == 2:
            help(True)
        
        else:
            help(False)
    else:
        help(False)

