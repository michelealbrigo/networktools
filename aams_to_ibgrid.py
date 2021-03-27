# -*- coding: utf-8 -*-
# importazione moduli
import datetime
import urllib
import os
# disabilita validazione SSL
import ssl
try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    pass
else:
    ssl._create_default_https_context = _create_unverified_https_context
# configurazione AAMS
aams_baseurl = 'https://www1.agenziadoganemonopoli.gov.it/files_siti_inibiti'
aams_filename = 'elenco_siti_inibiti.txt'
aams = aams_baseurl+'/'+aams_filename
# configurazione parametri locali
local_folder = os.path.expanduser('~')+'/Desktop'
# inizializzazione variabili
datestr = datetime.datetime.now().strftime("%Y%m%d")
blacklist_name = 'AAMS'+datestr
txt_filename = local_folder+'/'+blacklist_name+'.txt'
csv_filename = local_folder+'/'+blacklist_name+'.csv'
# scarica file da AAMS
urllib.urlretrieve(aams,txt_filename)
# trasforma file in CSV
ifile = open(txt_filename,'r')
ofile = open(csv_filename,'w+')
ofile.write('header-ruleset,name*,_new_name,type*,comment,disabled\n')
ofile.write('ruleset,'+blacklist_name+',,BLACKLIST,,False\n')
ofile.write('header-blacklistrule,action*,domain_name*,_new_domain_name,parent*\n')
for line in ifile:
	ofile.write('blacklistrule,REDIRECT,'+line.rstrip()+',,'+blacklist_name+'\n')
ifile.close()
ofile.close()
os.remove(txt_filename)