from scapy.all import sr1, IP, ICMP
import sys
import re


def check_ip(ipaddr):
	# check ip
	p = re.compile("(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}")
	check = p.match(ipaddr)

	print(check)
	if check is None: 
		print("Is not IP")
		sys.exit()



print(">> ICMP SCANNER START <<")

#chekc parameter
if len(sys.argv) < 2:
	print("no target IP")
	sys.exit()

ipaddr = sys.argv[1]
check_ip(ipaddr)


# creat packet
packet=IP(dst=ipaddr)/ICMP()
print("[DST] ", ipaddr)
print("[PACKET] ")
packet.show()

# send
cnt = 1
r = sr1(packet)
if r:
	print(cnt,"-------------------------------")
	r.show()
	print("-------------------------------",cnt)
else:
	print(cnt, ">WARNNING< packet send failed")
		

print(">> ICMP SCANNER END <<")

