#!/usr/bin/python3 

import shutil, os, re, _thread, socket, sys, re, yaml, logging as log

import dnslib as dns

DATA_PATH="/data"
APP_PATH="/app"
HOSTS_PATH="/app/hosts"

config = None
def main(args):
    setupLogging(True)

    setupEnvironment()

    global config
    config = readConfig(os.path.join(DATA_PATH, "config.yml"))

    s = setupSocket(config['socket']['address'], config['socket']['port'])
    
    startListen(s)

def setupEnvironment():
    if not os.path.exists(DATA_PATH):
        os.mkdir(DATA_PATH)

    (all, some) = copyAllFiles(f"{APP_PATH}/data/", DATA_PATH)
    if all:
        log.warning("Configuration-files were created!")
        log.warning(" Make sure to change them according to your setup")
    elif some:
        log.warning("Some configuration-files were recreated, because they were missing")

    if not os.path.exists(HOSTS_PATH):
        os.mkdir(HOSTS_PATH)

def copyAllFiles(src, dst, overwrite=False):
    all=True
    some=False
    for file in os.listdir(src):
        src_file = os.path.join(src, file)
        dst_file = os.path.join(dst, file)
        if os.path.isfile(src_file):
            if overwrite or not os.path.exists(dst_file):
                shutil.copyfile(src_file, dst_file)
                some=True
            else:
                all=False
    return (all, some)

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
    dmsg = dns.DNSRecord.parse(wire)
    return (address, dmsg)

def handleQuery(s, address, dmsg):
    log.info(f'{address[0]} |\tGot query {dmsg.header.id}')

    opcode = dmsg.header.opcode
    if opcode != dns.OPCODE.NOTIFY:
        log.error(f"{address[0]} |\tExpected opcode=NOTIFY, but was {dns.OPCODE[opcode]}")
        makeResponseWithRCode(s, address, dmsg, dns.RCODE.REFUSED)
        return False
    
    rcode = dmsg.header.rcode
    if rcode != dns.RCODE.NOERROR:
        log.error(f"{address[0]} |\tExpected rcode=NOERROR, but was {dns.RCODE[rcode]}")
        makeResponseWithRCode(s, address, dmsg, dns.RCODE.REFUSED)
        return False
    
    #flags = dmsg.flags
    #if flags != dns.flags.AA:
    #    print('Expected flags=AA, but was', dns.flags.to_text(flags))
    #    continue

    if len(dmsg.questions) != 1:
        log.error(f'{address[0]} |\tExpected question-len=1, but was {len(dmsg.question)}')
        makeResponseWithRCode(s, address, dmsg, dns.RCODE.FORMERR)
        return False
    
    # Check record in question
    record = dmsg.questions[0]
    
    r_qtype = record.qtype
    if r_qtype != dns.QTYPE.SOA:
        log.error(f'{address[0]} |\tExpected record to be SOA, but was {dns.QTYPE[r_qtype]}')
        makeResponseWithRCode(s, address, dmsg, dns.RCODE.FORMERR)
        return False
    
    name = str(record.qname)

    log.info(f'{address[0]} |\tNOTIFY for {name}')
    
    _thread.start_new_thread(updateNsData, (name,))

    response = dmsg.reply() # type: dns.message.Message
    response.header.aa = 1
    sendResponse(s, address, response)
    log.debug(f'{address[0]} |\tSent response')
    
    return True

def makeResponseWithRCode(socket, address, dmsg, rcode):
    response = dmsg.reply() # type: dns.message.Message
    response.header.rcode = rcode
    sendResponse(socket, address, response)

def sendResponse(socket, address, response):
    socket.sendto(response.pack(), address)

def setupLogging(verbose: bool):
    level = log.INFO
    format = '%(levelname)s:\t%(message)s'
    
    if verbose:
        level = log.DEBUG

    log.basicConfig(stream=sys.stdout, format=format, level=level)
    log.debug("Logging started")

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
        zone = zone[:-1]
        adaptedZone = adaptZoneName(zone)

        log.info(f'{adaptedZone} |\tUpdating NS-Data')

        dumpFile = f"{adaptedZone}.dump.js"
        if dumpZoneData(zone, dumpFile) != 0:
            raise Exception("Dumping data failed!")
        zone = adaptedZone
        
        hasToDelete = True

        adaptFileForRequire(zone, HOSTS_PATH, dumpFile)
        if dnscontrolPush(zone) != 0:
            raise Exception("Pushing data failed!")

        log.info(f'{adaptedZone} |\tFinished')
    except:
        log.warning(f'{adaptedZone} |\t{sys.exc_info()}')
        log.warning(f'{adaptedZone} |\tUpdating NS-Data failed!')

    if(hasToDelete):
        deleteFile(os.path.join(HOSTS_PATH, dumpFile))
    
def adaptZoneName(zone):
    if config['zone']['public-suffix'] != "" and zone.endswith(config['zone']['public-suffix']):
        adaptedZone = zone[:-len(config['zone']['public-suffix'])]
        return adaptedZone
    return zone

def dumpZoneData(zone, dumpFile):
    log.debug(f"{zone} |\tDumping to '{dumpFile}'..")
    return os.system(f"dnscontrol get-zones --creds {DATA_PATH}/creds.json --format=js --out={HOSTS_PATH}/{dumpFile} powerdns POWERDNS {zone}")

def deleteFile(file):
    log.debug(f"Deleting file '{file}'")
    os.remove(file)

ignoreLinesRexp = r"^\s*(var|D\(|DnsProvider\(|DefaultTTL\()"
def adaptFileForRequire(zone, path, dumpFile):
    log.debug(f"{zone} |\tRewriting file '{dumpFile}'..")

    dumpFilePath = os.path.join(path, dumpFile)

    with open(dumpFilePath, 'r') as fin:
        with open(f"{dumpFilePath}.tmp", 'w+') as fout:
            fout.write(f'D_EXTEND("{zone}",\n')

            for line in fin:
                if not re.match(ignoreLinesRexp, line):
                    fout.write(line)
    os.replace(f"{dumpFilePath}.tmp", dumpFilePath)

def dnscontrolPush(zone):
    log.debug(f'{zone} |\tPushing..')
    return os.system(f"dnscontrol push --config {DATA_PATH}/dnsconfig.js --creds {DATA_PATH}/creds.json --domains {zone}")

if __name__ == "__main__":
    sys.exit(main(sys.argv))
