# Cisco WLC to Infoblox DDI provisioning script
# Michele Albrigo - Area Networking - University of Verona - Italy
# Changelog
# 20190307 - v1.0 - initial release

import subprocess
import urllib.request
import urllib.error
import ssl
import base64
import json
import syslog
import datetime

# Global Configuration
wlcList = [['#####', '#####']]
wlcSNMPUser = '#####'
wlcSNMPVersion = '#####'
wlcSNMPLevel = '#####'
wlcSNMPAuth = '#####'
wlcSNMPAuthPhrase = '#####'
wlcSNMPPriv = '#####'
wlcSNMPPrivPhrase = '#####'
wlcSNMPCommunity = '#####'
remoteSites = {'#####': ['#####', '#####'],
               '#####': ['#####', '#####']}
apNetwork = '#####'
mainSiteNetworkSize = '#####'
wlc2ipamLogFile = '/var/log/wlc2ipam.log'
wlc2ipamSyslog = True
wlc2ipamSyslogFacility = syslog.LOG_LOCAL0
dnsSuffix = '.net.univr.it'
dnsView = 'Internal'

# WLC-side Configuration
wlcSNMPApBaseOid = '.1.3.6.1.4.1.14179.2.2.1.1.'

# IPAM-side Configuration
APIUser = '#####'
APIPassword = '#####'
ipamSrv = '#####'
ipamAPIVersion = '#####'

# Initialization
ssl._create_default_https_context = ssl._create_unverified_context
apDictionary = {}
hostDictionary = {}
result_raw = b''
if wlcSNMPVersion == '3':
    snmpParams = " -On -v" + wlcSNMPVersion + " -l " + wlcSNMPLevel + " -u " + wlcSNMPUser
    if wlcSNMPAuth != '' and (wlcSNMPLevel == 'authPriv' or wlcSNMPLevel == 'authNoPriv'):
        snmpParams = snmpParams + " -a " + wlcSNMPAuth + " -A'" + wlcSNMPAuthPhrase + "'"
    if wlcSNMPPriv != '' and wlcSNMPLevel == 'authPriv':
        snmpParams = snmpParams + " -x " + wlcSNMPPriv + " -X'" + wlcSNMPPrivPhrase + "'"
# TODO: SNMPv2
else:
    snmpParams = ''
ipamAuth = ('%s:%s' % (APIUser, APIPassword))
ipamAuthEncoded = base64.b64encode(ipamAuth.encode('ascii'))
ipamAPIBase = 'https://' + ipamSrv + '/wapi/v' + ipamAPIVersion + '/'
logfile = open(wlc2ipamLogFile, 'a+')
if wlc2ipamSyslog:
    syslog.openlog('wlc2ipam: ', facility=wlc2ipamSyslogFacility)
hostSingle = []
ipamJSON = {}


# IPAM Functions
# Generic Infoblox API read call
def ipam_api_read(ipamcall):
    ipamrequest = urllib.request.Request(ipamAPIBase + ipamcall)
    ipamrequest.add_header('Authorization', 'Basic %s' % ipamAuthEncoded.decode('ascii'))
    ipamresponse = urllib.request.urlopen(ipamrequest)
    return ipamresponse.read().decode('utf-8')


# Generic Infoblox API write call
def ipam_api_write(ipamcall, jsondata):
    ipamrequest = urllib.request.Request(ipamAPIBase + ipamcall)
    ipamrequest.add_header('Authorization', 'Basic %s' % ipamAuthEncoded.decode('ascii'))
    ipamrequest.add_header('Content-Type', 'application/json')
    ipamresponse = urllib.request.urlopen(ipamrequest, data=jsondata)
    return ipamresponse.read().decode('utf-8')


# Logging function
def log_message(message, priority):
    if wlc2ipamLogFile != '':
        logfile.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ': ' + message + '\n')
    if wlc2ipamSyslog:
        syslog.syslog(priority, message)


# Get all APs from WLC, write them into main data structure
log_message('Starting WLC2IPAM run...', syslog.LOG_INFO)
for wlc in wlcList:
    try:
        result_raw = subprocess.check_output("snmpwalk" + snmpParams + " " + wlc[0] + " " + wlcSNMPApBaseOid + "1",
                                             shell=True).split(b'\n')
        for ap in result_raw:
            if ap != b'':
                t1 = ap.split(b'=')
                t2 = t1[0].decode('utf-8')
                apDictionary[t2.replace('.1.3.6.1.4.1.14179.2.2.1.1.1.', '').rstrip(' ')] = \
                    [wlc[0], wlc[1], 'mac', 'name', 'ipaddr', 'serial']
    except subprocess.CalledProcessError:
        log_message('SNMP syntax error: ' + snmpParams, syslog.LOG_ERR)
for apID in apDictionary:
    try:
        apDictionary[apID][3] = subprocess.check_output("snmpget" + snmpParams + " " + apDictionary[apID][0] + " " +
                                            wlcSNMPApBaseOid + "3." + apID, shell=True).decode('utf-8').split('"')[1]
    except IndexError:
        log_message('WLC OID empty: ' + apID, syslog.LOG_ERR)
    try:
        temp_mac = subprocess.check_output("snmpget" + snmpParams + " " + apDictionary[apID][0] + " " +
                                         wlcSNMPApBaseOid + "33." + apID, shell=True).decode('utf-8').split(' ')
        apDictionary[apID][2] = temp_mac[3] + ":" + temp_mac[4] + ":" + temp_mac[5] + ":" + temp_mac[6] + ":" +\
                                temp_mac[7] + ":" + temp_mac[8]
    except UnicodeDecodeError:
        log_message('WLC returned malformed mac address for: ' + apDictionary[apID][3], syslog.LOG_ERR)
    apDictionary[apID][4] = subprocess.check_output("snmpget" + snmpParams + " " +
                                                  apDictionary[apID][0] + " " + wlcSNMPApBaseOid + "19." + apID,
                                                    shell=True).decode('utf-8').split(' ')[3].rstrip('\n')
    try:
        apDictionary[apID][5] = subprocess.check_output("snmpget" + snmpParams + " " + apDictionary[apID][0] + " " +
                                                        wlcSNMPApBaseOid + "17." + apID,
                                                        shell=True).decode('utf-8').split('"')[1]
    except IndexError:
        log_message('WLC OID empty: ' + apID, syslog.LOG_ERR)

# Rewrite apDictionary as hostDictionary (from WLC OID to Mac Address as key), purging APs we already have
for apID in apDictionary:
    # Check if AP is already on IPAM via mac address
    hostSingle == []
    try:
        hostSingle = json.loads(ipam_api_read("record:host?mac=" + apDictionary[apID][2].lower()))
    except urllib.error.HTTPError as error:
        log_message('HTTP error ' + str(error.code) + ', ap ' + apDictionary[apID][3] + ' might not exist in IPAM',
                    syslog.LOG_WARNING)
    # Create a dictionary of new APs with IPAM-ready data
    if hostSingle == []:
        hostDictionary[apDictionary[apID][2]] = [apDictionary[apID][3], apDictionary[apID][5], 'network']

# Write new APs into IPAM
for k, v in hostDictionary.items():
    # Check the right network to write the AP in
    try:
        location = remoteSites[v[0].split('-')[0]]
    except KeyError:
        location = ['0', mainSiteNetworkSize]
    hostNetwork = apNetwork + '.' + location[0] + '.0/' + location[1]
    # Prepare its JSON
    hostJSON = json.dumps(dict([
        ('configure_for_dns', True),
        ('name', v[0]+dnsSuffix),
        ('view', dnsView),
        ('comment', v[1]),
        ('ipv4addrs', [dict([
            ('ipv4addr', 'func:nextavailableip:' + hostNetwork),
            ('configure_for_dhcp', True),
            ('use_for_ea_inheritance', True),
            ('mac', k)
            ])]
         )
    ]))
    try:
        ipam_api_write("record:host", hostJSON.encode('utf-8'))
        log_message('Created ap ' + v[0], syslog.LOG_INFO)
    except urllib.error.HTTPError as error:
        log_message('Problem contacting IPAM: HTTP error ' + str(error.code) + ' about ap ' + v[0], syslog.LOG_ERR)

log_message('Ending WLC2IPAM run...', syslog.LOG_INFO)
# Close logs
if wlc2ipamSyslog:
    syslog.closelog()
if (not wlc2ipamLogFile == '') and ('logfile' in globals()):
    logfile.close()

# End