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


def dlog(msg):
    print msg

def get_id(hook):
    Result = hook.fetchone()
    if str(Result) == 'None':
        return 'None'
    else:
        return str(Result[0])

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
def update_cursor_ip(ip):
	global cursor
	cursor.execute("SELECT IP_ID FROM T_IP WHERE IP = %s", (ip,))


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
        CIP = f.readline().rstrip('\n')
        data = f.readline()

        # Update la table Client si pas client ne fait rien
        cursor.execute('select CLT_ID from T_CLIENT where UID=%s', (UID, ))
        CLT_ID = get_id(cursor)

        # si pas UID ... stop, drop file, report, checker par php in
        if (CLT_ID == 'Null'):
            log('CLT_ID not found')
            break
        cursor.execute(
            'UPDATE T_CLIENT set PUSH_TIME=now() where CLT_ID=%s', (CLT_ID,))

    except:
        dlog('error reading report')
    report = json.loads(data)
    for line in report:
        # print line
            # Scan for http://
        MURL = ''
        IP = ''
        TYPE_ID = 0  # Not scanned
        candidateF = False
        try:
            subreg = re.search(commonregex, line)
            #//phpsubreg = re.search('<\?php', urllib.unquote_plus(subreg.group(1)))
            INJ_HIT = subreg.group(3)
            M_TIME = subreg.group(2)
            IP = subreg.group(1)
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
            MURL_ID = get_id(cursor)
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
            FILE_ID = get_id(cursor)
            if (FILE_ID == 'None'):
                dlog("insert FILE ")
                cursor.execute(
                    'insert into T_FILE (FMD5, FSHA, FSSDEEP) VALUES (%s, %s, %s)',
                    (FMD5,
                     FSHA,
                     FSSDEEP,
                     ))
                FILE_ID = cursor.lastrowid
        # Update la table injection
        cursor.execute(
            'select INJ_ID from T_INJ where INJ_HIT = %s', (INJ_HIT,))
        INJ_ID = get_id(cursor)
        if (INJ_ID == 'None'):
            dlog("insert Injection")
            cursor.execute(
                'insert into T_INJ (INJ_HIT) VALUES (%s) ', (INJ_HIT,))
            INJ_ID = cursor.lastrowid

		#---------------------------------------
        # Update la table IP Attanquant
		#---------------------------------------
        update_cursor_ip(IP) 
        IP_ID = get_id(cursor)
        if (IP_ID == 'None'):
            dlog("insert new attaquant IP")
            json_geoip_data = get_geoip(CIP)			
			# latitude longitude country city isp
            cursor.execute(
                'INSERT INTO T_IP (IP,ATT,LASTSEEN) VALUES (%s, True, now())', (IP,))
            IP_ID = cursor.lastrowid
        else:
            dlog("Update IP")
            dlog(
                'UPDATE T_IP SET LASTSEEN=now(),ATT=True WHERE IP_ID = ' +
                IP_ID)
            cursor.execute("UPDATE T_IP SET LASTSEEN = now(), ATT = True WHERE IP_ID = %s", (IP_ID,))

        # Update la client IP
        update_cursor_ip(CIP)
        IP_ID = get_id(cursor)
        if (IP_ID == 'None'):
            dlog("insert new client IP")
            geoip = get_geoip(CIP)
            cursor.execute(
                'INSERT INTO T_IP (IP,CLT,LASTSEEN) VALUES (%s, True, now())', (CIP,))
            IP_ID = get_id(cursor)
        else:
            dlog("Update IP")
            cursor.execute(
                'UPDATE T_IP SET CLT=True, LASTSEEN=now() WHERE IP_ID = %s', (IP_ID,))

        # Updated Client
        cursor.execute('UPDATE T_CLIENT SET PUSH_TIME=now() WHERE CLT_ID=%s', (CLT_ID,))

        # Insert HIT
        dlog('insert HIt')
        if (TYPE_ID != 3):
            cursor.execute(
                'INSERT INTO T_HIT (CLT_ID,INJ_ID,TYPE_ID,MURL_ID,HIT_TIME) VALUES (%s, %s, %s,%s, now())',
                (CLT_ID,
                 INJ_ID,
                 TYPE_ID,
                 MURL_ID,
                 ))
        else:
            cursor.execute(
                'INSERT INTO T_HIT (CLT_ID,INJ_ID,TYPE_ID,FILE_ID,HIT_TIME) VALUES (%s, %s, %s,%s, now())',
                (CLT_ID,
                 INJ_ID,
                 TYPE_ID,
                 FILE_ID,
                 ))

        # Commit database
        cursor.connection.commit()

        # close file and move to outq
        f.close()
        try:
            shutil.move(log, config.get("queue", "out") + '/')
        except:
            pass

db.close()
