#-*- coding: UTF-8 -*-
import socket
import time
import struct
import select
import traceback
import os

from inspect import currentframe, getframeinfo
from elastalert.enhancements import BaseEnhancement
from elastalert.util import elastalert_logger


frameinfo = getframeinfo(currentframe())

class AlertReq:
    pduType=16973833
    alertId=""
    alertCode=0
    faultType=0
    faultValue=0
    faultSrc=""

    def __init__(self, alertId, alertCode, faultType, faultValue, faultSrc):
        self.alertId = alertId
        self.alertCode = alertCode
        self.faultType = faultType
        self.faultValue = faultValue
        self.faultSrc = faultSrc

    def getBodyLength(self):
        msgLen = 8
        msgLen += 4
        msgLen += 4
        msgLen += 4
        msgLen += 2
        msgLen += len(self.faultSrc)
        return msgLen
    
    def encodeReq(self):
        buf = struct.pack('!i', self.pduType)
        buf += struct.pack('!i', self.getBodyLength())
        buf += self.alertId.ljust(8, '\0').encode()
        buf += struct.pack('!i', self.alertCode)
        buf += struct.pack('!i', self.faultType)
        buf += struct.pack('!i', self.faultValue)
        buf += struct.pack('!h', len(self.faultSrc))
        buf += self.faultSrc.encode()
        return buf

class SendAlertEnhancement(BaseEnhancement):
    ip = "211.233.76.208"
    port = 22001
    alertReq = None

    def sendAlert(self):
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.ip, self.port))

            sock.send(self.alertReq.encodeReq())
            ready = select.select([sock], [], [], 3000)
            if ready[0]:
                pduType = struct.unpack('!i', sock.recv(4))[0]
                if pduType == 16973834:
                    bodyLen = struct.unpack('!i', sock.recv(4))[0]
                    resCode = struct.unpack('!i', sock.recv(bodyLen))[0]
                    elastalert_logger.info(
                        "(res_alert) resCode:%d" % resCode
                        )
                else:
                    elastalert_logger.error(
                        "Unknown Pdu Type:%d", pduType
                        )
        finally:       
            if sock != None:      
                sock.close()

    def process(self, match):
        try:
            elastalert_logger.info(match)
            alertId=None
            faultSrc=""

            if 'tsid' not in match and 'rsid' not in match:
                return

            if 'tsid' in match :
                tsid = match['tsid']
                alertId = tsid.replace('0', '').upper()
            else:
                alertId = "RCSTS1"

            if match['_index'].find("rcsts-alertlog-") >= 0: 
                faultType = 10003
                faultValue = 0
                message = match['description']
                if message.find("Queue is Abnormal.") >= 0 :
                    faultType = 10011
                    queueName = message.split(':')[1].split(' ')[0]
                    queueSize = message.split(':')[2]
                    
                    faultValue = int(queueSize)
                    faultSrc = queueName + " (Time:" + match['@localtime'].split(' ')[1].replace(':', '') +")"
                elif message.find("Tail is less than header") >=0 or message.find("FileSize is over Max Queue Size") >=0 or message.find("Buffer Size is") > 0:
                    # Abnormal File Queue
                    faultType = 10011
                    queueName = os.path.basename(message.split(" ")[1]).replace("]", "")
                    faultSrc = "%s Abnormal" % queueName
                elif message.find("Disconnected") >= 0 or message.find("Not Connected") >= 0:
                    if message.find("rsId:") > 0:
                        faultType = 10011
                        rsId = message[message.find("rsId:") + len("rsId:"):message.find(" ip:")]
                        ip = message[message.find("ip:") + len("ip:"):message.find(" port:")]
                        port = message[message.find("port:") + len("port:"):len(message)]

                        faultSrc = ("%s:%s Disconnected") % (ip, port)
                    elif message.find("Database") >= 0:
                        faultType = 10011
                        faultSrc = "Database Disconnect."
                    else:
                        # AlertId : TSCode
                        faultType = 10003
                        alertId = match['tscode']
                        carrier = message[message.find("carrier:") + len("carrier:"):message.find(" url:")]

                        faultSrc = "Disconnect."
                elif message.find("JsonParseException") > 0 :
                    faultType = 10011
                    faultSrc = "JsonException"
                else:
                    elastalert_logger.info(
                        "[%s:%d] Not matched. index:%s" % (frameinfo.filename, frameinfo.lineno, match['_index'])
                        )
                    return
            elif match['_index'].find("rcsrs-rsltlog-") >= 0:
                faultValue = match['num_hits']
                carrier = None
                if match['carrier'] == "20001" :
                    carrier = "SKT"
                elif match['carrier'] == "20002" :
                    carrier = "KT" 
                else :
                    carrier = "LGU"

                if match['ibrslt']== "2000":
                    faultType = 10011

                    faultSrc = ("%s Timeout") % carrier
                elif match['netrslt'] == "59001" or match['netrslt'] == "59002":
                    # AlertId : TSCode
                    alertId = match['tscode']
                    faultType = 10003

                    faultSrc = ("%s code:%s") % (carrier, match['netrslt'])
                else:
                    elastalert_logger.info(
                        "[%s:%d] Not matched. index:%s" % (frameinfo.filename, frameinfo.lineno, match['_index'])
                        )
                    return
            elif match['_index'].find("rcsrs-tran-") >= 0:
                faultValue = match['num_hits']
                faultType = 10011

                if 'elapse_time' in match:
                    tscode = match['tscode']
                    rsid = match['rsid']
                    faultSrc = ("%s Send Delay") % rsid
                else:
                    elastalert_logger.info(
                        "[%s:%d] Not matched. index:%s" % (frameinfo.filename, frameinfo.lineno, match['_index'])
                        )
                    return
            elif match['_index'].find("rcsts-queue-") >= 0:
                faultValue = match['queue_size']
                faultType = 10011
                faultSrc = match['queue_name']
            else:
                elastalert_logger.info(
                    "[%s:%d] Not matched. index:%s" % (frameinfo.filename, frameinfo.lineno, match['_index'])
                    )
                return
            
            if alertId != None and len(faultSrc) > 0:
                elastalert_logger.info("(req_alert) alsertId:%s faultType:%d faultValue:%d faultSrc:%s" % (alertId, faultType, faultValue, faultSrc))
                self.alertReq = AlertReq(alertId, 1003, faultType, faultValue, faultSrc)
                self.sendAlert()
        except Exception as e:
            elastalert_logger.error(traceback.format_exc())

