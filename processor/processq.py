#!/usr/bin/python

# Process the input queue
import re
import json
import hashlib
import urllib
import MySQLdb
import ConfigParser
import glob
import shutil
import httplib
import sys

def dlog(msg):
    print msg

def getid():
    global cursor
    return str(cursor.fetchone()[0])

#TODO: Rename !! 
def get_id(ip):
    global cursor
    cursor.execute('SELECT id FROM ips WHERE address = %s ' , (ip, ))
    ip = cursor.fetchone()
    if str(ip) == 'None':
        return 'None'
    else:
        return str(ip[0])

# Get GeoIP information
#---------------------------------------
# ip (Visitor IP address, or IP address specified as parameter)
# country_code (Two-letter ISO 3166-1 alpha-2 country code)
# country_code3 (Three-letter ISO 3166-1 alpha-3 country code)
# country (Name of the country)
# region_code (Two-letter ISO-3166-2 state / region code)
# region (Name of the region)
# city (Name of the city)
# postal_code (Postal code / Zip code)
# continent_code (Two-letter continent code)
# latitude (Latitude)
# longitude (Longitude)
# dma_code (DMA Code)
# area_code (Area Code)
# asn (Autonomous System Number)
# isp (Internet service provider)
# timezone (Time Zone)
#---------------------------------------
def get_geoip(ip):
	conn = httplib.HTTPConnection("www.telize.com")
	conn.request("GET","/geoip/"+ip)
	response = conn.getresponse()
	#TODO: handle response.status != 200 ...
	json_data = json.loads(response.read())	
	conn.close()
	return json_data

# Get cursor for a IP
#---------------------------------------
def create_ip(ip, attacker = False, client = False, bck = False ):
	global cursor	
	#cursor.execute("INSERT ips.id FROM ips WHERE address = %s", (ip,))	
	json_ip = get_geoip(ip)
	cursor.execute("INSERT INTO ips (address, country, city, country_code, latitude, longitude, isp, timezone, attacker, client, bck, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,now())",
	 (json_ip['ip'],
	json_ip['country'],
	json_ip['city'],
	json_ip['country_code'].lower(),
	json_ip['latitude'],
	json_ip['longitude'],
	json_ip['isp'],
	json_ip['timezone'],
	attacker,
	client,
	bck,))
	return cursor.lastrowid

# TODO: udpate des champs attacker, client, bck si ils changent ... ou s'ajoutent.
def update_ip(ip, attacker = False, client = False, bck = False ):
	global cursor
	cursor.execute("UPDATE ips SET updated_at = NOW() WHERE address = %s", (ip,))


# Read configuration file
#---------------------------------------
config = ConfigParser.ConfigParser()
config.read('config.cfg')


##### START ######
#---------------------------------------
commonregex = '^[\S]*\s([0-9a-f\:\.]{7,})(?:\s[\S]*){2}\s\[([\d\/\w\s:+]*)]\s"([\S]{1,}\s(\S*)\s[\S\.\/]{1,})"\s\d'

logs = ['./sample/out.txt']

# Open database connection
#---------------------------------------
db = MySQLdb.connect(config.get("sql", "server"),
                     config.get("sql", "user"),
                     config.get("sql", "pass"),
                     config.get("sql", "dbase"))

# prepare a cursor object using cursor() method
cursor = db.cursor()


# load file list
#---------------------------------------
logs = glob.glob(config.get("queue", "in") + '/*')

for log in logs:
    try:
        dlog('processing ' + log)
        f = open(log, 'r')
        UID = f.readline().rstrip('\n')
        CLIENT_IP = f.readline().rstrip('\n')
        data = f.readline()
    except:
        dlog('error reading report')

    #---------------------------------------
 		#   Check and update du Client
	  #   * Update la table Client si pas client ne fait rien
		#---------------------------------------
    cursor.execute('SELECT CLT_ID FROM T_CLIENT WHERE UID = %s', (UID, ))
    CLIENT_ID = getid()

    # si pas de CLIENT_ID ... stop, drop file, report, checker par php in !
    if (CLIENT_ID == 'None'):
        log('CLT_ID not found')
        #TODO: erase and report error !
        break
    
    print("Start updating data from client id: %s with IP: %s" % (CLIENT_ID, CLIENT_IP))
    
    # Update last push time
    cursor.execute('UPDATE T_CLIENT SET PUSH_TIME=now() WHERE CLT_ID = %s', (CLIENT_ID,))
    
    #---------------------------------------
 		#   Update la table IP pour le Client
		#---------------------------------------
    CLIENT_IP_ID = get_id(CLIENT_IP)
    if (CLIENT_IP_ID == 'None'):
        dlog("Insert new client IP: "+CLIENT_IP)
        CLIENT_IP_ID = create_ip(CLIENT_IP, client = True)
    else:
        dlog("Update client IP: "+CLIENT_IP)
        update_ip(CLIENT_IP, client = True)
    
    
    #---------------------------------------
 		#         Load user's data
		#---------------------------------------
    report = json.loads(data)
    for line in report:
        # print line
            # Scan for http://
        MURL = ''
        ATTACKER_IP = ''
        TYPE_ID = 0  # Not scanned
        candidateF = False
        try:
            subreg = re.search(commonregex, line)
            #//phpsubreg = re.search('<\?php', urllib.unquote_plus(subreg.group(1)))
            INJ_HIT = subreg.group(3)
            M_TIME = subreg.group(2)
            ATTACKER_IP = subreg.group(1)
            httpsubreg = re.search(
                '((ftp|http)://(\S*))\s',
                urllib.unquote_plus(
                    subreg.group(3)))
            candidate = (httpsubreg.group(1))
            candidateF = True
        except:
            pass
        finally:
            if (candidateF):
                MURL = candidate
                HITn = INJ_HIT.replace(MURL, '<RFI_INJ>', 1)
                if (INJ_HIT == HITn):
                    HITn = INJ_HIT.replace(
                        urllib.quote_plus(MURL),
                        '<RFI_INJ>',
                        1)
                INJ_HIT = HITn
            else:
                phpreg = re.search('(<\?php\S*)', subreg.group(3))
                if (phpreg is not None):
                    TYPE_ID = 3  # Not scanned
                    MURL = ''
                    M_FILE = phpreg.group(1)
                    HITn = INJ_HIT.replace(M_FILE, '<RFI_INJ>', 1)
                    if (INJ_HIT == HITn):
                        HITn = INJ_HIT.replace(
                            urllib.quote_plus(M_FILE),
                            '<RFI_INJ>',
                            1)
                    INJ_HIT = HITn
                    FMD5 = hashlib.md5(M_FILE).hexdigest()
                    FSHA = hashlib.sha256(M_FILE).hexdigest()
                    FSSDEEP = ''

                    # Save file
                    fout = open(config.get("repo", "folder") + '/' + FMD5, 'w')
                    fout.write(M_FILE)
                    fout.close()

        if (TYPE_ID != 3):
            # Fill the malware Url Table
            cursor.execute('select MURL_ID from T_MURL where MURL=%s', (MURL,))
            MURL_ID = getid()
            if (MURL_ID == 'None'):
                dlog("insert murl")
                # Si MURL_ID pas trouve
                cursor.execute(
                    "INSERT INTO T_MURL (MURL) values (%s)", (MURL,))
                MURL_ID = cursor.lastrowid
        else:
            # It's a direct injection
            # Md5 Sum the injection sauve et insert dans db si inexistant
            cursor.execute(
                'select FILE_ID from T_FILE where FSHA = %s', (FSHA,))
            FILE_ID = getid()
            if (FILE_ID == 'None'):
                dlog("insert FILE ")
                cursor.execute(
                    'insert into T_FILE (FMD5, FSHA, FSSDEEP) VALUES (%s, %s, %s)',
                    (FMD5,
                     FSHA,
                     FSSDEEP,))
                FILE_ID = cursor.lastrowid
        # Update la table injection
        cursor.execute('select INJ_ID from T_INJ where INJ_HIT = %s', (INJ_HIT,))
        
        INJ_ID = getid()
        if (INJ_ID == 'None'):
            dlog("insert Injection")
            cursor.execute('insert into T_INJ (INJ_HIT) VALUES (%s) ', (INJ_HIT,))
            INJ_ID = cursor.lastrowid

				#---------------------------------------
        #   Update la table IP Attanquant
				#---------------------------------------        
        IP_ID = get_id(ATTACKER_IP)
        if (IP_ID == 'None'):
            dlog("insert new attacker IP")            
            IP_ID = create_ip(ATTACKER_IP, attacker = True)
        else:
            #TODO: Mettre dans un tableau les ip et faire un seul update pour toute les IP !!!
            dlog("Update last_seen attacker IP: "+ATTACKER_IP)
            update_ip(ATTACKER_IP)


        # Insert HIT
        # TODO: check if not already added !!!
        dlog('Insert Hit')
        if (TYPE_ID != 3):
            cursor.execute(
                'INSERT INTO T_HIT (CLT_ID,INJ_ID,TYPE_ID,MURL_ID,HIT_TIME) VALUES (%s, %s, %s,%s, now())',
                (CLIENT_ID,
                 INJ_ID,
                 TYPE_ID,
                 MURL_ID,
                 ))
        else:
            cursor.execute(
                'INSERT INTO T_HIT (CLT_ID,INJ_ID,TYPE_ID,FILE_ID,HIT_TIME) VALUES (%s, %s, %s,%s, now())',
                (CLIENT_ID,
                 INJ_ID,
                 TYPE_ID,
                 FILE_ID,
                 ))

        # Commit database
        db.commit()

        # close file and move to outq
        f.close()
        try:
            shutil.move(log, config.get("queue", "out") + '/')
        except:
            pass

db.close()
