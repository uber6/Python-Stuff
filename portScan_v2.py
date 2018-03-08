import argparse
import ipaddress
from socket import *

def scanPorts(finalHost, tgtPort, portresult):
    '''Scans whether the port is open or closed using TCP connect method.

    finalHost = string
    tgtPort = integer'''

    try:
        connTCP = socket(AF_INET, SOCK_STREAM)
        connTCP.connect((finalHost, tgtPort))
        connTCP.send(b'HTTP/1.1\r\n')
        connTCPin = connTCP.makefile('r')
        connTCPout = connTCP.makefile('w')
        banner = ['(nothing received)']
        try:
            results = connTCP.recv(100)
            if results:
                banner = str(results.decode('ascii')).split('\n')
        except:
            pass
        portresult[finalHost]['Open'][tgtPort] = banner[0]
    except:
        portresult[finalHost]['Closed'][tgtPort] = '(closed)'
        pass
    finally:
        connTCP.close()
        return(portresult)

def testHost(tgtHost):
    '''Validate whether a given host/IP address is valid.
    This will not check whether the host/IP address is up/down.
    Removes invalid hosts."

    tgtHost = string'''

    try:
        tgtIP = gethostbyname(tgtHost)
        return (tgtHost)
    except:
        print("   [* WARNING *] \"{}\" not scanned. Host not available.\n".format(tgtHost.upper()))

def validHosts(tgtHosts):
    '''Validates whether a given host/IP address is valid.
    This will not check whether the host/IP address is up/down.
    Once all hosts/IP address are validated, the function returns a new list of valid hosts/IP addresses, with all invalid ones removed.

    tgtHosts = list (item = string)'''

    validList = []
    for item in tgtHosts:
        if '/' in item:
            for addr in list(ipaddress.IPv4Network(item, strict=False))[1:-1]:
                if testHost(str(addr)):
                    validList.append(testHost(str(addr)))
        else:
            if testHost(item):
                validList.append(testHost(item))

    return(validList)

def scanHosts(tgtHosts, tgtPorts):
    '''Scans the give set of Hostnames/IP addresses against the given set of ports.
    Each Hostname/IP address is first validated before the ports are scanned.

    tgtHosts = list (object = string)
    tgtPorts = list (object = integer)'''

    print("\n[*] Testing for valid hosts\n")

    finalHosts = validHosts(tgtHosts)

    finalresult = {}

    if finalHosts:
        setdefaulttimeout(.2)
        print("[*] Ports to scan: {}\n".format(tgtPorts))
        for finalHost in finalHosts:
            print("  [-] Scanning host {}".format(finalHost.upper()))
            portresult = {finalHost:{'Open':{}, 'Closed':{}}}
            for tgtPort in tgtPorts:
                portresult = scanPorts(finalHost, tgtPort, portresult)
            finalresult[finalHost] = portresult[finalHost]

    else:
        print("\n!!!!!!!!!!!! [!!!] NO VALID HOSTS TO SCAN [!!!] !!!!!!!!!!!!\n")

    print('\n======================= SCAN RESULTS =======================\n')
    for host in finalHosts:
        print("[+] Result for host \"{:}\":".format(host.upper()))
        portclosed = []
        for item in finalresult[host]['Open']:
            print('\t- Open   (TCP):\t{:5}\t{}'.format(item, finalresult[host]['Open'][item]))
        for item in finalresult[host]['Closed']:
            portclosed.append(item)
        print('\n\tThe following ports are closed:\t', sorted(portclosed))
        print()

    print("\n====================== SCAN COMPLETE =======================\n")

def parsePort(itemSet):
    '''Parses the given set of ports and returns a sorted list.

    itemSet = list (object = string)'''

    newSet = []

    if itemSet[0] == 'all':
        for i in range(1024):
            newSet.append(i)
    else:
        newSet = [int((item.strip()).strip(',')) for items in itemSet for item in (items.strip(',')).split(',')]

    return(sorted(newSet))

def parseIP(itemSet):
    '''Parses the given set of Hostnames/IP addresses and returns a sorted list.

    itemSet = list (object = string)'''

    newSet = [((item.strip()).strip(',')) for items in itemSet for item in (items.strip(',')).split(',')]

    return(sorted(newSet))

def main():
    '''Parses through the arguments when executed.
    Type 'python portScan_v2.py -h | --help' for more information.'''

    parser = argparse.ArgumentParser(description = "\n\tTARGET:\tMultiple targets can be separated by commas (,) or spaces ( ). A CIDR notation (/) may be used for a range. \n\tPORT:\tMultiple ports can be separated by commas or spaces.\n\t\tPort 'all' will scan for common ports (0-1023). ***If -p/--port option is skipped, ports 21, 22, 53, 80, and 443 are scanned.")
    parser.add_argument('-H', '--host', nargs = '+', dest = 'tgtHosts', type = str, help = "specify target host[s] separated by comma or space. A CIDR notation may be used.")
    parser.add_argument('-p', '--port', nargs = '+', dest = 'tgtPorts', type = str, default = ['21', '22', '53', '80', '443'], help = "specify target port[s] separated by comma or space. 'all' scans all common ports.")

    args = parser.parse_args()

    if (args.tgtHosts == None):
        print(parser.print_help())
        exit(0)

    scanHosts(parseIP(args.tgtHosts), parsePort(args.tgtPorts))

if __name__ == "__main__":
    main()