# 基于SocketServer的极简服务器
from socketserver import TCPServer, StreamRequestHandler

class Handler(StreamRequestHandler):
    def handle(self):
        addr = self.request.getpeername()
        print('Got connectio from', addr)
        self.wfile.write(b'Thank you for connecting')

server = TCPServer(('',1234),Handler)
server.serve_forever()