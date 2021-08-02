#!/usr/bin/python3 

import os, re, _thread, subprocess, socket, datetime, getopt, sys, re, atexit, yaml, logging as log
from pathlib import Path

import dns.flags
import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.name

from typing import cast

config = None
def main(args):
    setupLogging(True)
    log.debug("Logging started")

    global config
    config = readConfig("/data/config.yml")

    s = setupSocket(config['socket']['address'], config['socket']['port'])
    
    startListen(s)

def setupSocket(address, port):
    # IPv4/IPv6-check
    if address == "" or ":" in address: 
        family = socket.AF_INET6
    else:
        family = socket.AF_INET
    
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.bind((address, port))
    return s

def startListen(s):
    log.debug(f'Now listening')
    while True:
        (address, dmsg) = receiveFromWire(s)
        _thread.start_new_thread(handleQuery, (s, address, dmsg))

def receiveFromWire(s):
    (wire, address) = s.recvfrom(512)
    dmsg = dns.message.from_wire(wire)
    return (address, dmsg)

def handleQuery(s, address, dmsg):
    log.info(f'{address[0]} |\tGot query')

    opcode = dmsg.opcode()
    if opcode != dns.opcode.NOTIFY:
        log.error(f"{address[0]} |\tExpected opcode=NOTIFY, but was {dns.opcode.to_text(opcode)}")
        makeResponseWithRCode(s, address, dmsg, dns.rcode.REFUSED)
        return False
    
    rcode = dmsg.rcode()
    if rcode != dns.rcode.NOERROR:
        log.error(f"{address[0]} |\tExpected rcode=NOERROR, but was {dns.rcode.to_text(rcode)}")
        makeResponseWithRCode(s, address, dmsg, dns.rcode.FORMERR)
        return False
    
    #flags = dmsg.flags
    #if flags != dns.flags.AA:
    #    print('Expected flags=AA, but was', dns.flags.to_text(flags))
    #    continue

    if len(dmsg.question) != 1:
        log.error(f'{address[0]} |\tExpected question-len=1, but was {len(dmsg.question)}')
        makeResponseWithRCode(s, address, dmsg, dns.rcode.FORMERR)
        return False
    
    # Check record in question
    record = dmsg.question[0]
    
    r_datatype = record.rdtype
    if r_datatype != dns.rdatatype.SOA:
        log.error(f'{address[0]} |\tExpected record to be SOA, but was {r_datatype}')
        makeResponseWithRCode(s, address, dmsg, dns.rcode.FORMERR)
        return False
    
    log.info(f'{address[0]} |\tNOTIFY for {record.name}')
    
    _thread.start_new_thread(updateNsData, (record.name,))

    response = dns.message.make_response(dmsg) # type: dns.message.Message
    response.flags |= dns.flags.AA
    sendResponse(s, address, response)
    log.debug(f'{address[0]} |\tSent response')
    
    return True

def makeResponseWithRCode(socket, address, dmsg, rcode):
    response = dns.message.make_response(dmsg) # type: dns.message.Message
    response.set_rcode(rcode)
    sendResponse(socket, address, response)

def sendResponse(socket, address, response):
    wire = response.to_wire(cast(dns.name.Name, response))
    socket.sendto(wire, address)

def setupLogging(verbose: bool):
    level = log.INFO
    format = '%(levelname)s:\t%(message)s'
    
    if verbose:
        level = log.DEBUG

    log.basicConfig(stream=sys.stdout, format=format, level=level)

def readConfig(file: str):
    log.debug(f"Reading config '{file}'..")

    if not os.path.isfile(file):
        raise OSError(2, file)
    
    return readYamlFile(file)

def readYamlFile(file: str):
    with open(file, "r") as f:
        return yaml.load(f, Loader=yaml.FullLoader)

def updateNsData(zone):
    hasToDelete = False
    try:
        zone = str(zone)[:-1]
        adaptedZone = adaptZoneName(zone)

        log.info(f'{adaptedZone} |\tUpdating NS-Data')

        dumpFile = f"{adaptedZone}.dump.js"
        if dumpZoneData(zone, dumpFile) != 0:
            raise Exception("Dumping data failed!")
        zone = adaptedZone
        
        hasToDelete = True

        adaptFileForRequire(zone, dumpFile)
        if dnscontrolPush(zone) != 0:
            raise Exception("Pushing data failed!")

        log.info(f'{adaptedZone} |\tFinished')
    except:
        log.error(f'{adaptedZone} |\t{sys.exc_info()}')
        log.error(f'{adaptedZone} |\tUpdating NS-Data failed!')

    if(hasToDelete):
        deleteFile(dumpFile)
    
def adaptZoneName(zone):
    if config['zone']['public-suffix'] != "" and zone.endswith(config['zone']['public-suffix']):
        adaptedZone = zone[:-len(config['zone']['public-suffix'])]
        return adaptedZone
    return zone

def dumpZoneData(zone, dumpFile):
    log.debug(f"{zone} |\tDumping to '{dumpFile}'..")
    return os.system(f"dnscontrol get-zones --creds /data/creds.json --format=js --out={dumpFile} powerdns POWERDNS {zone}")

def deleteFile(file):
    log.debug(f"Deleting file '{file}'")
    os.remove(file)

ignoreLinesRexp = r"^\s*(var|D\(|DnsProvider\(|DefaultTTL\()"
def adaptFileForRequire(zone, dumpFile):
    log.debug(f"{zone} |\tRewriting file '{dumpFile}'..")

    with open(dumpFile, 'r') as fin:
        with open(f"{dumpFile}.tmp", 'w+') as fout:
            fout.write(f'D_EXTEND("{zone}",\n')

            for line in fin:
                if not re.match(ignoreLinesRexp, line):
                    fout.write(line)
    os.replace(f"{dumpFile}.tmp", dumpFile)

def dnscontrolPush(zone):
    log.debug(f'{zone} |\tPushing..')
    return os.system(f"dnscontrol push --config /data/dnsconfig.js --creds /data/creds.json --domains {zone}")

if __name__ == "__main__":
    sys.exit(main(sys.argv))
