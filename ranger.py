from scapy.all import *
from threading import Thread
import pandas
import time
import os

# networks dataframe initialization
networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
# set the index BSSID (MAC address of the AP)
networks.set_index("BSSID", inplace=True)

def callback(packet):
    if packet.haslayer(Dot11Beacon):
        # MAC address extraction
        bssid = packet[Dot11].addr2
        ssid = packet[Dot11Elt].info.decode()
        try:
            dbm_signal = packet.dBm_AntSignal
        except:
            dbm_signal = "N/A"
        # network stats
        stats = packet[Dot11Beacon].network_stats()
        # trying to get AP channel
        channel = stats.get("channel")
        # reveals the crypto
        crypto = stats.get("crypto")
        networks.loc[bssid] = (ssid, dbm_signal, channel, crypto)

# Network dataframe content
def print_all():
    while True:
        os.system("clear")
        print(networks)
        time.sleep(0.5)

def change_channel():
    ch = 1
    while True:
        os.system(f"iwconfig {interface} channel {ch}")
        # switches channel from 1 to 14 each 0.5sec
        ch = ch % 14 + 1
        time.sleep(0.5)

if __name__ == "__main__":
    # check interface name using iwconfig
    interface = "wlan0mon"
    # Thread that prints all the networks
    printer = Thread(target=print_all)
    printer.daemon = True
    printer.start()
    # channel changer initialized
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()
    # sniffing starts
    sniff(prn=callback, iface=interface)