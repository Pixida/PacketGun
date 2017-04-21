# PacketGun
UDP packet sender for recorded RawCap (*.pcap) dumps including sending on localhost.

The tool first reads the packages from a *.pcap file, which have been recorded e.g. in RawCapture or Wireshark. The payload of these UDP packages is then sent either to the original destination like stated in the *.pcap or to another address/port.

## PacketGun does:
- work in Python 2.7 (tested) and Python 3.5 (tested)
- require the dpkt package (available in pip)
- require the mtTkinter package (only when used with Python 2.7) (available in pip)
- only accept *.pcap files
- only send UDP packages
- also send to localhost

## Features:
- Open and read *.pcap files
- Altering of destination IP and port
- Setting of package frequency and start index
- Decoding of payload (16 character hex to double)
- Format output of decoded message via the config.ini
- A progress bar displaying the progress
- Play, stop, pause and next buttons for flow control
- Console like output of processed packages

## Best practice:
1. Capture traffic via Wireshark or RawCap (when sending to localhost)
2. Filter the dump to only contain desired packages
3. Start PacketGun, open the *.pcap and reproduce the traffic
