# Infoblox DDI to Cisco ISE provisioning script
# Michele Albrigo - Area Networking - University of Verona - Italy
# Changelog
# 20190307 - v1.1 - Adjusted for Python coding recommendations
#                   Reworked some parts to better handle exceptions
#                   Improved logging, added Syslog support
#                   Comment translation
# 20190305 - v1.0 - initial release
import urllib.request
import urllib.error
import ssl
import base64
import json
import datetime
import syslog

# Local configuration variables
APIUser = '#####'
APIPassword = '#####'
ipamSrv = '#####'
ipamAPIVersion = '#####'
iseSrv = '#####'
ipamCategoryAttrib = '#####'
ipam2iseLogFile = '/var/log/ipam2ise.log'
ipam2iseSyslog = True
ipam2iseSyslogFacility = syslog.LOG_LOCAL7
localCSV = '/usr/local/share/mab_devices.csv'

# Initialization
ssl._create_default_https_context = ssl._create_unverified_context
ipamDevicesList = []
ipamCategoryList = []
iseGroupDict = {}
addedDevicesList = []
removedDevicesList = []
logfile = open(ipam2iseLogFile, 'a+')
if ipam2iseSyslog:
    syslog.openlog('ipam2ise: ', facility=ipam2iseSyslogFacility)

# IPAM-side configuration
ipamAuth = ('%s:%s' % (APIUser, APIPassword))
ipamAuthEncoded = base64.b64encode(ipamAuth.encode('ascii'))
ipamAPIBase = 'https://' + ipamSrv + '/wapi/v' + ipamAPIVersion + '/'


# ISE-side configuration
iseAPIBase = 'https://' + iseSrv + ':9060/ers/config/'
iseAuth = ('%s:%s' % (APIUser, APIPassword))
iseAuthEncoded = base64.b64encode(ipamAuth.encode('ascii'))


# IPAM Functions
# Generic Infoblox API call
def ipam_api_call(ipamcall):
    ipamrequest = urllib.request.Request(ipamAPIBase + ipamcall)
    ipamrequest.add_header('Authorization', 'Basic %s' % ipamAuthEncoded.decode('ascii'))
    ipamresponse = urllib.request.urlopen(ipamrequest)
    return ipamresponse.read().decode('utf-8')


# ISE Functions
# Generic ISE read API call
def ise_api_call_read(isecall, isereturntype):
    iserequest = urllib.request.Request(iseAPIBase + isecall)
    iserequest.add_header('Authorization', 'Basic %s' % iseAuthEncoded.decode('ascii'))
    iserequest.add_header('Accept', isereturntype)
    iseresponse = urllib.request.urlopen(iserequest)
    return iseresponse.read().decode('utf-8')


# Generic ISE write API call
def ise_api_call_write(isecall, isedata):
    isedataencoded = isedata.encode('ascii')
    iserequest = urllib.request.Request(iseAPIBase + isecall, data=isedataencoded, method='POST')
    iserequest.add_header('Authorization', 'Basic %s' % iseAuthEncoded.decode('ascii'))
    iserequest.add_header('Accept', 'application/json')
    iserequest.add_header('Content-Type', 'application/json')
    iseresponse = urllib.request.urlopen(iserequest)
    return iseresponse.read().decode('utf-8')


# Generic ISE delete API call
def ise_api_call_delete(isecall):
    iserequest = urllib.request.Request(iseAPIBase + isecall, method='DELETE')
    iserequest.add_header('Authorization', 'Basic %s' % iseAuthEncoded.decode('ascii'))
    iserequest.add_header('Accept', 'application/json')
    iseresponse = urllib.request.urlopen(iserequest)
    return iseresponse.read().decode('utf-8')


# Logging function
def log_message(message, priority):
    if ipam2iseLogFile != '':
        logfile.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ': ' + message + '\n')
    if ipam2iseSyslog:
        syslog.syslog(priority, message)


# Get all possible values for our Extensible Attribute on IPAM
try:
    ipamAttributeJSON = json.loads(ipam_api_call("extensibleattributedef?name=" +
                                                 ipamCategoryAttrib +
                                                 "&_return_fields=list_values"))
    for isegroupid in (ipamAttributeJSON[0])['list_values']:
        ipamCategoryList.append(isegroupid['value'])
except urllib.error.HTTPError as error:
    log_message('Problem contacting IPAM: HTTP error ' + str(error.code), syslog.LOG_ERR)

# Build a minimal list of devices [group,name,mac]
for category in ipamCategoryList:
    try:
        ipamDevicesJSON = json.loads(
            ipam_api_call("record:host?_return_fields=aliases,ipv4addrs.host,ipv4addrs.mac,extattrs&*" +
                          ipamCategoryAttrib + "=" + category))
        for device in ipamDevicesJSON:
            try:
                if device['ipv4addrs'][0]['mac'] != '00:11:00:00:11:00':
                    ipamDevicesList.append(category + ',' + device['ipv4addrs'][0]['host'] + ',' +
                                           device['ipv4addrs'][0]['mac'] + '\n')
            except KeyError:
                try:
                    log_message('IPAM host ' + device['ipv4addrs'][0]['host'] + ' has incomplete data', syslog.LOG_ERR)
                    print(device)
                except KeyError:
                    log_message('IPAM host ' + device['_ref'] + ' has incomplete data', syslog.LOG_ERR)
    except urllib.error.HTTPError as error:
        log_message('Problem reading IPAM on category: ' + category + ', HTTP error: ' +
                    str(error.code), syslog.LOG_ERR)

# Open the local DB or create an empty list if it does not exist
try:
    localFile = open(localCSV, 'r')
    localDevicesList = localFile.readlines()
    localFile.close()
except IOError:
    localDevicesList = []

# Compute differences between IPAM and local DB
# Added devices (IPAM-DB)
addedDevicesListConc = list(set(ipamDevicesList) - set(localDevicesList))
for item in addedDevicesListConc:
    splitItem = item.split(',')
    addedDevicesList.append(splitItem)
# Removed devices (DB-IPAM)
removedDevicesListConc = list(set(localDevicesList) - set(ipamDevicesList))
for item in removedDevicesListConc:
    splitItem = item.split(',')
    removedDevicesList.append(splitItem)
# Untouched devices
untouchedDevicesListConc = list(set(localDevicesList)-set(removedDevicesListConc))

# Keep untouched hosts in our local DB
try:
    localFile = open(localCSV, 'w')
    for item in untouchedDevicesListConc:
        localFile.write(item)
    localFile.close()
except IOError:
    log_message('Problem writing local DB', syslog.LOG_ERR)

# Get ISE Group-ID for each Extensible Attribute value on IPAM
for group in ipamCategoryList:
    try:
        iseGroupsJSON = json.loads(ise_api_call_read("endpointgroup?filter=name.EQ." + group, 'application/json'))
        iseGroupDict[group] = iseGroupsJSON['SearchResult']['resources'][0]['id']
    except IndexError:
        iseGroupDict[group] = ''
    except urllib.error.HTTPError as error:
        log_message('Problem contacting ISE reading group: ' + group + ', HTTP error: ' + str(error.code),
                    syslog.LOG_ERR)

# Create groups on ISE if not present (and save their Group-ID)
for isegroupname, isegroupid in iseGroupDict.items():
    if len(isegroupid) == 0:
        try:
            ise_api_call_write('endpointgroup', '{  "EndPointGroup" : {  "name" : "' + isegroupname +
                               '", "description" : "Provisioned by IPAM2ISE" } }')
            iseGroupsJSON = json.loads(ise_api_call_read("endpointgroup?filter=name.EQ." + isegroupname,
                                                         'application/json'))
            iseGroupDict[isegroupname] = iseGroupsJSON['SearchResult']['resources'][0]['id']
        except urllib.error.HTTPError as error:
            log_message('Problem contacting ISE creating group ' + isegroupname + ' HTTP error: ' + str(error.code),
                        syslog.LOG_ERR)

# If there is any variation, update both ISE and the local DB
if (addedDevicesList.__len__() > 0) or (removedDevicesList.__len__() > 0):
    # Remove devices from ISE
    for item in removedDevicesList:
        try:
            itemMac = item[2].rstrip('\n').upper()
            itemID = json.loads(ise_api_call_read('endpoint?filter=mac.EQ.' +
                                                  itemMac, 'application/json'))['SearchResult']['resources'][0]['id']
            ise_api_call_delete('endpoint/' + itemID)
            log_message('Removed endpoint ' + item[1], syslog.LOG_NOTICE)
        except urllib.error.HTTPError as error:
            log_message('Problem contacting ISE, HTTP error: ' + str(error.code), syslog.LOG_ERR)

    # Add devices on ISE and local DB
    try:
        localFile = open(localCSV, 'a')
        for item in addedDevicesList:
            try:
                jdict = {'name': item[1],
                         'description': item[1],
                         'mac': item[2].rstrip('\n').upper(),
                         'groupId': iseGroupDict[item[0]],
                         'staticGroupAssignment': 'true'}
                ise_api_call_write("endpoint", '{ \n "ERSEndPoint" : ' + json.dumps(jdict) + ' \n}')
                localFile.write(item[0]+','+item[1]+','+item[2])
                log_message('Added endpoint ' + item[1], syslog.LOG_NOTICE)
            except urllib.error.HTTPError as error:
                if error.code == 500:
                    localFile.write(item[0] + ',unknown,' + item[2])
                    log_message('Problem writing on ISE: mac address ' + item[2].rstrip('\n').upper() +
                                ' already exists', syslog.LOG_ERR)
                else:
                    log_message('Problem writing on ISE: error ' + str(error.code), syslog.LOG_ERR)
        localFile.close()
        log_message('Updated local DB', syslog.LOG_NOTICE)
    except IOError:
        log_message('Problem writing local DB', syslog.LOG_ERR)
else:
    log_message('Dry run', syslog.LOG_INFO)

if ipam2iseSyslog:
    syslog.closelog()
if (not ipam2iseLogFile == '') and ('logfile' in globals()):
    logfile.close()

# End