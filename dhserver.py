
from socket import *
import random

List_available_IP = ['192.168.0.12','192.168.0.14','192.168.0.10','192.168.0.15','192.168.0.23','192.168.0.32','192.168.0.43']
Used_IP = list()
def Ip_offer(ip_address):
	offer = b''
	for i in ip_address.split('.'):
		#print(str(i))
		offer +=int(i).to_bytes(1,'big' )
	#print("Ip in bytes: ", offer)
	return offer
def DCHPOFFER(ip_address,xid,mac):
	pkt = b''
	pkt += b'\x02' #Op code
	pkt += b'\x01' #htype
	pkt += b'\x06' #lenght
	pkt += b'\x00' #hops
	print("xid bytes: ",bytes.fromhex(xid))
	pkt += bytes.fromhex(xid) #xid
	#print("pkt: ", pkt) # b'\x02\x01\x06\x00\xa9\x85\x94\x0b'
	pkt += b'\x00\x00' #secs
	pkt += b'\x00\x00' #flags
	pkt += b'\x00\x00\x00\x00' # Client IP Address ciadder
	pkt += Ip_offer(ip_address) # Yiadder
	pkt += Ip_offer('192.168.0.1') # Server Ip siadder siadder
	pkt += Ip_offer('0.0.0.0') #Relay Ip Address giadder
	pkt += bytes.fromhex(str(mac).replace(':','')) # chaddr

	pkt += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	pkt += b'\x00' * 67
	pkt += b'\x00' *125
	pkt += b'\x63\x82\x53\x63'
	

	pkt += b'\x35\x01\x02'
	pkt += b'\x01\x04\xff\xff\xff\x00'
	pkt += b'\x03\x04'+Ip_offer('192.168.0.1')
	pkt += b'\x33\x04\x00\x01\x51\x80'
	pkt += b'\x51\x04'+Ip_offer('192.168.0.1')
	pkt += b'\xff'
	return pkt

def DHCPACK(ip_address,xid,mac):
        pkt = b''
        pkt += b'\x02' #Op code
        pkt += b'\x01' #htype
        pkt += b'\x06' #lenght
        pkt += b'\x00' #hops
        print("xid bytes: ",bytes.fromhex(xid))
        pkt += bytes.fromhex(xid) #xid
        #print("pkt: ", pkt) # b'\x02\x01\x06\x00\xa9\x85\x94\x0b'
        pkt += b'\x00\x00' #secs
        pkt += b'\x00\x00' #flags
        pkt += b'\x00\x00\x00\x00' # Client IP Address ciadder
        pkt += Ip_offer(ip_address) # Yiadder
        pkt += Ip_offer('192.168.0.1') # Server Ip siadder siadder
        pkt += Ip_offer('0.0.0.0') #Relay Ip Address giadder
        pkt += bytes.fromhex(str(mac).replace(':','')) # chaddr

        pkt += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        pkt += b'\x00' * 67
        pkt += b'\x00' *125
        pkt += b'\x63\x82\x53\x63'


        pkt += b'\x35\x01\x05'
        pkt += b'\x01\x04\xff\xff\xff\x00'
        pkt += b'\x03\x04'+Ip_offer('192.168.0.1')
        pkt += b'\x33\x04\x00\x01\x51\x80'
        pkt += b'\x51\x04'+Ip_offer('192.168.0.1')
        pkt += b'\xff'
        return pkt



def Search(Used_IP,val):
	for i in range(0,len(Used_IP),1):
		if Used_IP[i] == val:
			print("IP address already in use")
			return 1
	return 0
def Checker_For_DISC(check_val):
	if check_val == b'\x03':
		while check_val == b'\x03':
			msg,addr = s.recvfrom(1024)
			compare = msg[241:243]
			if compare[1:] == b'\x01':
				check_val = compare[1:]
				return msg
	else:
		msg,addr = s.recvfrom(1024)
		compare = msg[241:243]
		if compare[1:] == b'\x01':
			check_val = compare[1:]
			return msg
			
def Build(xid,mac,x,msg):
	print(len(msg))
	check_ack = msg[241:243]
	print(check_ack[1:])
	print('DISCOVER CHECK: ', msg[241:243])
	#pre-check
	check_val = check_ack[1:]
	msg = Checker_For_DISC(check_val)
	
	print('check_val',check_val)
	xid, mac = Parser_xidmac(msg)	
	print('XID: ',xid)
	print('MAC: ',mac)	

	x = int(x)
	while x != 0:
		if x < 4:
			tmp_msg, addr = s.recvfrom(1024)
			check_ack = tmp_msg[241:243]
			check_val = check_ack[1:]
			msg = Checker_For_DISC(check_val)
			xid, mac = Parser_xidmac(msg)
		ip_address = ''
		ran = random.randint(0,len(List_available_IP)-1)
		if Search(Used_IP,List_available_IP[ran]) == 0:
			r = random.randint(ran,len(List_available_IP)-1)
			ip_address = List_available_IP[r]
		else:
			ip_address = List_available_IP[ran]
		print("IP Address: ", ip_address)

		pkt = DHCPOFFER(ip_address,xid,mac)
		s.sendto(pkt,DHCP_CLIENT)
		msg, addr = s.recvfrom(1024)

		xid_ack, mac_ack = Parser_xidmac(msg)
		ack_pkt = DHCPACK(ip_address,xid_ack,mac_ack)
		s.sendto(ack_pkt,DHCP_CLIENT)
		x -=1

def Parser_xidmac(msg):
	xid = msg[4:8].hex()
	mac = msg[28:34].hex(":")
	return xid,mac

def setUp(msg,addr,x):
	#print(msg)
	xid,mac = Parser_xidmac(msg)
	print('xid: ', xid)
	print('mac: ', mac)
	Build(xid,mac,x,msg)



#main
if __name__ == '__main__':
	DHCP_SERVER = ('', 67)
	DHCP_CLIENT = ('255.255.255.255', 68)

	# Create a UDP socket
	s = socket(AF_INET, SOCK_DGRAM)

	# Allow socket to broadcast messages
	s.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)

	# Bind socket to the well-known port reserved for DHCP servers
	s.bind(DHCP_SERVER)

	# Recieve a UDP message
	msg, addr = s.recvfrom(1024)
	x = input('Enter the number of clients')
	print( 'Number entered' +x)
	setUp(msg,addr,x)





#starter code
#Print the client's MAC Address from the DHCP header
#print("PRINTING MEGS ",len(msg))
#print(msg)
#Printing xid
#xid = ''
#for i in range(4,8):
	#xid += format(msg[i],'x')
	#print(":" + format(msg[i], 'x'),end = '')
#print('xid: ',xid)
#print("addr",addr)
#print("Client's MAC Address is " + format(msg[28], 'x'), end = '')
#for i in range(29, 34):
	#print(":" + format(msg[i], 'x'), end = '')
#print()
# Send a UDP message (Broadcast)
#s.sendto(b'Hello World!', DHCP_CLIENT)
