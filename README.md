# Background
One day I came across a thread on the new [PMKID](https://hashcat.net/forum/thread-7717.html) attack.  I wanted to shorten the steps needed to obtain the data to run [hashcat](https://hashcat.net/hashcat/) and built this tool.

# Gist
pmkid2hashcat does not inject if the outcome is already known.  Once you have a captured string that is the input for hashcat, there is no sense in making duplicates, nor interacting with the same ESSID again.  This simplicity also means that if you miss a PMKID due to something such as perhaps a channel switch; pmkid2hashcat will not retry.

pmkid2hashcat does not control or care about channel hopping.  An easy way to hop channels without too much work is simply utilizing airodump-ng at the same time.  Let airodump-ng control the hops and pmkid2hashcat prepare the hashes for hashcat intake without having to do a conversion that a tool like hcxdumptool requires.

The simplistic nature of pmkid2hashcat is by design.  Be seen the least amount of times as possible.

hashes.file is for hashcat, hashes.log is for humans.  Both logs are appended to and never overwritten.

# How-to
Create the input for hashcat with a specific ESSID (Optional on --essid):
```
python3 ./pmkid2hashcat.py -i <Monitor Mode NIC> --essid vulnNetwork
```

Run hashcat:
```
hashcat -m 22000 hashes.file <wordlist>
```

# Years have gone by
The other day I decided to take a peek at this repo and see if I remembered how to do all this.  When I built the [original code](https://github.com/stryngs/scripts/commit/ce72827305f2c00096f1e0f2f389ac70bfee01c9) I used scapy to cobble together what worked with the hardware on hand.

As the years go by, so do the layers.  The layers I refer to are those in scapy.  `[Raw]` used to mark where the PMKID existed, with [2.7.0](https://github.com/secdev/scapy/releases/tag/v2.7.0) this no longer works for the PMKID gathering concept.

What used to be:
```
        stream = hexstr(packet[Raw].load, onlyhex = 1).split(' ')
        pmkid = ' '.join(stream[len(stream) - 16:]).replace(' ', '')
```

What is now:
```
pmkid = ''.join(hexstr(packet[EAPOL_KEY].key_data, onlyhex = 1).split()[-16:])
```
