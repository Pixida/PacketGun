import codecs
import datetime

try:
    import SocketServer as sose
except ImportError:
    import socketserver as sose


class MyUDPHandler(sose.BaseRequestHandler):
    """ Small Receiver for testing PacketGun """

    def handle(self):
        timp = datetime.datetime.now().isoformat()
        addr = self.client_address[0]
        port = self.client_address[1]
        data = codecs.encode(self.request[0].strip(), 'hex_codec').decode()
        print("{}: {}:{} wrote: {}".format(timp, addr, port, data))


if __name__ == "__main__":
    HOST, PORT = "localhost", 8082

    server = sose.UDPServer((HOST, PORT), MyUDPHandler)

    server.serve_forever()
