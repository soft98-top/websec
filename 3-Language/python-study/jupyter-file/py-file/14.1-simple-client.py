## 简单的客户端
import socket
s= socket.socket()
host = socket.gethostname()
port = 1234
s.connect((host,port))
print(s.recv(1024))