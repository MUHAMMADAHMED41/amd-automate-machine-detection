#!/usr/bin/python3.4
import time
import logging
import sys
import os
import fcntl
import asterisk.agi
from asterisk.agi import AGIError
import pymysql as mysql_connector
import websocket
import configparser
import json

# --- Configuration ---
LOG_DIR = "/var/log/amd"
CONFIG_FILE = '/etc/astguiclient.conf'
WEBSOCKET_URL = "ws://api.amdy.io:2700"
AUDIO_FD = 3
TIMEOUT = 5  # seconds
CHUNK_SIZE = 9500
MIN_DATA_SIZE = 2000
SAMPLE_RATE = 8000

# --- Logging Setup ---
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)
LOG_FILE = "{}/amd_{}.log".format(LOG_DIR, time.strftime('%Y%m%d'))
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler(sys.stderr)]
)
log = logging.getLogger(__name__)

# --- Utility Functions ---
def get_mysql_config():
    """Loads MySQL config from /etc/astguiclient.conf"""
    try:
        config = {}
        with open(CONFIG_FILE, 'r') as file:
            for line in file:
                line = line.strip()
                if line and not line.startswith('#') and '=>' in line:
                    key, value = line.split('=>', 1)
                    config[key.strip()] = value.strip()
        return {
            'user': config.get('VARDB_user'),
            'password': config.get('VARDB_pass'),
            'host': config.get('VARDB_server'),
            'db': config.get('VARDB_database'),
            'port': int(config.get('VARDB_port', 3306))
        }
    except Exception as e:
        log.error("Failed to load MySQL config: {}".format(e))
        raise

def connect_to_db():
    """Establishes a MySQL connection."""
    try:
        conn = mysql_connector.connect(**get_mysql_config())
        log.debug("DB connection successful.")
        return conn
    except mysql_connector.Error as e:
        log.error("DB connection failed: {}".format(e))
        raise

def get_elapsed_time_ms(additional_string=""):
    """Returns elapsed time since script start in milliseconds."""
    return "{}-AMDY.IO-{}".format(int((time.time() - script_start_time) * 1000), additional_string)

def extract_lead_id(callerid):
    """Extract lead_id from callerid."""
    if not callerid:
        log.debug("Callerid is empty, cannot extract lead_id")
        return None
    callerid = callerid.replace('"', '').split(' ')[0]
    try:
        if len(callerid) >= 20:
            lead_id = int(callerid[10:20])
            log.debug("Extracted lead_id from callerid: {}".format(lead_id))
            return lead_id
    except (ValueError, IndexError):
        log.debug("Failed to extract lead_id from callerid")
    return None

def update_honeypot_status(lead_id, callerid, uniqueid):
    """Updates database records for honeypot detection."""
    conn = None
    try:
        now = time.strftime('%Y-%m-%d %H:%M:%S')
        now_epoch = int(time.time())
        conn = connect_to_db()
        cursor = conn.cursor()
        e_uniqueid = uniqueid.split('.')[0] if '.' in uniqueid else uniqueid
        query = "SELECT start_epoch, uniqueid FROM vicidial_log WHERE lead_id=%s AND uniqueid LIKE %s ORDER BY call_date DESC"
        cursor.execute(query, (lead_id, '{}%'.format(e_uniqueid)))
        results = cursor.fetchall()

        if len(results) > 1:
            old_uniqueid = results[1][1]
            query = "DELETE FROM vicidial_log WHERE uniqueid=%s AND lead_id=%s LIMIT 1"
            cursor.execute(query, (old_uniqueid, lead_id))
            log.debug("Deleted duplicate vicidial_log: {}".format(old_uniqueid))

        if results:
            vd_start_epoch = results[0][0]
            if not vd_start_epoch:
                log.warning("Empty start_epoch for uniqueid: {}, skipping update".format(uniqueid))
                return
            vd_seconds = now_epoch - int(vd_start_epoch)
            query = "UPDATE vicidial_log SET status='HPOT', end_epoch=%s, length_in_sec=%s WHERE uniqueid=%s AND lead_id=%s"
            cursor.execute(query, (now_epoch, vd_seconds, uniqueid, lead_id))
            log.debug("Updated vicidial_log: {}".format(uniqueid))

        else:
            end_epoch = now_epoch + 3
            query = """INSERT INTO vicidial_log (uniqueid, lead_id, call_date, start_epoch, status, user, processed)
                       VALUES (%s, %s, %s, %s, 'HPOT', 'VDAD', 'N')"""
            cursor.execute(query, (uniqueid, lead_id, now, now_epoch))
            log.debug("Inserted vicidial_log: {}".format(uniqueid))

        query = "UPDATE vicidial_list SET status='HPOT' WHERE lead_id=%s"
        cursor.execute(query, (lead_id,))
        log.debug("Updated vicidial_list: {}".format(lead_id))

        conn.commit()
    except Exception as e:
        log.error("Failed to update honeypot status: {}".format(e))
    finally:
        if conn:
            conn.close()

def process_chunk(agi, ws, buf):
    """Processes an audio chunk and handles AMD results."""
    try:
        ws.send_binary(buf)
        log.debug("AMD: Sent {} bytes".format(len(buf)))
        res = str(ws.recv())
        log.debug("AMD: Received: {}".format(res))
        stats = get_elapsed_time_ms(res)

        if 'HONEYPOT' in res:
            log.info("Honeypot detected")
            callerid = agi.env.get('agi_calleridname', 'unknown')
            uniqueid = agi.env.get('agi_uniqueid', 'unknown')
            log.debug("Raw agi_calleridname: {}".format(callerid))
            lead_id = extract_lead_id(callerid)
            if lead_id:
                update_honeypot_status(lead_id, callerid, uniqueid)
            else:
                log.warning("Could not find lead_id, skipping status update")
            try:
                agi.set_variable("AMDSTATUS", "HONEYPOT")
                agi.set_variable("AMDCAUSE", res)
                agi.set_variable('AMDSTATS', stats)
            except AGIError as e:
                log.error("AGIError setting variables: {}".format(e))
            return True

        elif 'HUMAN' in res:
            log.info("Human detected")
            try:
                agi.set_variable('AMDSTATUS', "HUMAN")
                agi.set_variable('AMDCAUSE', "HUMAN")
                agi.set_variable('AMDSTATS', stats)
            except AGIError as e:
                log.error("AGIError setting variables: {}".format(e))
            return True

        elif 'AMD' in res:
            log.info("Machine detected")
            try:
                agi.set_variable("AMDSTATUS", "MACHINE")
                agi.set_variable("AMDCAUSE", "MACHINE")
                agi.set_variable('AMDSTATS', stats)
            except AGIError as e:
                log.error("AGIError setting variables: {}".format(e))
            return True

    except Exception as e:
        log.error("AMD processing error: {}".format(e))
        stats = get_elapsed_time_ms('NETERR')
        try:
            agi.set_variable('AMDSTATUS', "HUMAN")
            agi.set_variable('AMDCAUSE', 'NETERR')
            agi.set_variable('AMDSTATS', stats)
        except AGIError as e:
            log.error("AGIError setting error variables: {}".format(e))
        return True
    return False

# --- Main AGI Script ---
def startAGI():
    """Main AGI script."""
    agi = asterisk.agi.AGI()
    ani = agi.env.get('agi_callerid', 'unknown')
    vid = agi.env.get('agi_calleridname', 'unknown')
    did = agi.env.get('agi_extension', 'unknown')
    channel = agi.env.get('agi_channel', 'unknown')
    log.info("Starting AGI - ANI: {}, VID: {}, DID: {}, Channel: {}".format(ani, vid, did, channel))

    try:
        ws = websocket.create_connection(WEBSOCKET_URL, timeout=3)
        config_msg = json.dumps({"config": {"sample_rate": SAMPLE_RATE, "VID": vid}})
        ws.send(config_msg)
        log.info("Websocket connected and configured.")
    except Exception as e:
        log.error("Websocket connection failed: {}".format(e))
        try:
            agi.set_variable('AMDSTATUS', "HUMAN")
            agi.set_variable('AMDCAUSE', 'NETERR')
            agi.set_variable('AMDSTATS', '0')
        except AGIError as e:
            log.error("AGIError setting variables: {}".format(e))
        return

    try:
        fcntl.fcntl(AUDIO_FD, fcntl.F_SETFL, os.O_NONBLOCK)
        total_data = 0
        data = b''
        start_time = time.time()

        while True:
            try:
                chunk = os.read(AUDIO_FD, CHUNK_SIZE)
                data += chunk
                if not chunk:
                    log.info("No audio data. Total: {}".format(total_data))
                    try:
                        agi.set_variable('AMDSTATUS', "HANGUP")
                        agi.set_variable('AMDSTATS', '0')
                    except AGIError as e:
                        log.error("AGIError setting variables: {}".format(e))
                    break

                if len(data) > MIN_DATA_SIZE:
                    total_data += len(data)
                    log.debug("Processing {} bytes. Total: {}".format(len(data), total_data))
                    if process_chunk(agi, ws, data):
                        return
                    data = b''

            except OSError as err:
                if err.errno == 11:  # EAGAIN
                    if (time.time() - start_time) > TIMEOUT:
                        log.warning("Timeout reached. Total: {}".format(total_data))
                        if total_data < 1:
                            try:
                                agi.set_variable('AMDSTATUS', 'NOAUDIO')
                                agi.set_variable('AMDCAUSE', 'NOAUDIO')
                            except AGIError as e:
                                log.error("AGIError setting variables: {}".format(e))
                        else:
                            try:
                                agi.set_variable('AMDSTATUS', "INTERR")
                                agi.set_variable('AMDCAUSE', 'NETERR')
                            except AGIError as e:
                                log.error("AGIError setting variables: {}".format(e))
                        try:
                            agi.set_variable('AMDSTATS', '0')
                        except AGIError as e:
                            log.error("AGIError setting variables: {}".format(e))
                        return
                    time.sleep(0.1)
                    continue

    except Exception as e:
        log.error("Audio processing error: {}".format(e))
        try:
            agi.set_variable('AMDSTATUS', "HUMAN")
            agi.set_variable('AMDCAUSE', 'NETERR')
            agi.set_variable('AMDSTATS', '0')
        except AGIError as e:
            log.error("AGIError setting variables: {}".format(e))
    finally:
        log.info("Closing websocket")
        try:
            ws.send('{"eof" : 1}')
            ws.close()
        except Exception as e:
            log.error("Websocket close error: {}".format(e))

# --- Script Entry Point ---
script_start_time = time.time()
try:
    startAGI()
except Exception as e:
    log.critical("Fatal error: {}".format(e))
    sys.exit(1)