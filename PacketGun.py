#! python

import dpkt
import time
import socket
import struct
import codecs
import itertools
from threading import Thread, Event

try:
    import mttkinter.mtTkinter as tk
    import ttk
    import tkFileDialog as fd
    import Queue as qu
    import ConfigParser as cp
except ImportError:
    import tkinter as tk
    import tkinter.ttk as ttk
    import tkinter.filedialog as fd
    import queue as qu
    import configparser as cp


class PacketGun(tk.Frame):
    """
    PacketGun sends recoded UDP packages to the desired IP address (incl. localhost).
    See the README.txt for more information.
    """

    def __init__(self, parent, *args, **kwargs):
        """
        Constructor

        :param parent: tkinter root from main
        """
        tk.Frame.__init__(self, parent, *args, **kwargs)
        parent.wm_title("PacketGun")
        parent.iconbitmap(default="logo.ico")
        #
        self._play_event = Event()  # start sending event
        self._stop_event = Event()  # stop sending event
        self._pause_event = Event()  # pause sending event
        self._next_event = Event()  # send next package and keep paused
        self._pcap_file = tk.StringVar(self, "<-- PLEASE OPEN PCAP FILE")  # path to *.pcap file
        self._pcap_list = []  # list of from *.pcap file parsed packages
        self._shoot_wait = tk.DoubleVar(self, "")  # sleep time between packages (in seconds) -> 0: original delay
        self._start_index = tk.IntVar(self, "")  # start sending packets from this index
        self._dest_ip = tk.StringVar(self, "")  # destination ip
        self._dest_port = tk.IntVar(self, "")  # destination port
        self._decode = tk.BooleanVar(self, 1)  # toggle data decoding on / off
        #
        config = cp.ConfigParser()
        config.read("config.ini")
        self._decode_mapping = eval(config.get("decoder", "mapping"))
        self._decode_format = eval(config.get("decoder", "format"))
        #
        # file dialog with open button and label
        frame = tk.Frame(self)
        tk.Button(frame, text="OPEN", command=self._parse, padx=46).pack(side="left", expand=False, fill="y")
        tk.Label(frame, textvar=self._pcap_file, anchor="w", padx=5).pack(side="right", expand=True, fill="both")
        frame.pack(side="top", expand=False, fill="both")
        #
        # all possible arguments bundled in a joint frame
        arguments = tk.Frame(self)
        frame = tk.Frame(arguments)
        tk.Label(frame, text="Use these inputs to overwrite\nvalues from the *.pcap file.", anchor="w",
                 justify="left").pack(side="left", expand=True, fill="both")
        frame.pack(side="left", expand=True, fill="both", padx=5)
        # destination IP
        frame = tk.Frame(arguments)
        tk.Label(frame, text="DEST. IP\ndefault: empty", anchor="e").pack(side="left", expand=True, fill="both")
        tk.Entry(frame, textvar=self._dest_ip, justify="center", width=16).pack(side="left", expand=True, fill="both")
        frame.pack(side="left", expand=True, fill="both", padx=5)
        # destination Port
        frame = tk.Frame(arguments)
        tk.Label(frame, text="DEST. PORT\ndefault: 0", anchor="e").pack(side="left", expand=True, fill="both")
        tk.Entry(frame, textvar=self._dest_port, justify="center", width=8).pack(side="left", expand=True, fill="both")
        frame.pack(side="left", expand=True, fill="both", padx=5)
        # sleep seconds entry
        frame = tk.Frame(arguments)
        tk.Label(frame, text="PAUSE BETWEEN PACKAGES\ndefault: 0.0 (seconds)", anchor="e").pack(
            side="left", expand=True, fill="both")
        tk.Entry(frame, textvariable=self._shoot_wait, justify="center", width=8).pack(
            side="left", expand=True, fill="both")
        frame.pack(side="left", expand=True, fill="both", padx=5)
        # start package index
        frame = tk.Frame(arguments)
        tk.Label(frame, text="PACKAGE START INDEX\ndefault: 0", anchor="e").pack(
            side="left", expand=True, fill="both")
        tk.Entry(frame, textvariable=self._start_index, justify="center", width=8).pack(
            side="left", expand=True, fill="both")
        frame.pack(side="left", expand=True, fill="both", padx=5)
        # decode data checkbox
        frame = tk.Frame(arguments)
        tk.Label(frame, text="DECODE DATA\ndefault: on", anchor="e").pack(
            side="left", expand=True, fill="both")
        tk.Checkbutton(frame, variable=self._decode).pack(side="left", expand=True, fill="both")
        frame.pack(side="left", expand=True, fill="both", padx=5)
        arguments.pack(side="top", expand=False, fill="both", pady=5, padx=2)
        #
        # progress bar
        self._progress_bar = ttk.Progressbar(self, orient='horizontal', mode='determinate')
        self._progress_bar.pack(side="top", expand=False, fill="both", padx=2)
        #
        # all buttons are greyed out at the beginning but will come available if logical
        frame = tk.Frame(self)
        self._button_start = tk.Button(frame, text="PLAY", state="disabled", command=self._start)
        self._button_start.pack(side="left", expand=True, fill="both")
        self._button_stop = tk.Button(frame, text="STOP", state="disabled", command=self._stop)
        self._button_stop.pack(side="left", expand=True, fill="both")
        self._button_pause = tk.Button(frame, text="PAUSE", state="disabled", command=self._pause)
        self._button_pause.pack(side="left", expand=True, fill="both")
        self._button_next = tk.Button(frame, text="NEXT", state="disabled", command=self._next)
        self._button_next.pack(side="left", expand=True, fill="both")
        frame.pack(side="top", expand=False, fill="both", padx=2)
        #
        # "console" output window
        frame = tk.Frame(self, width=800, height=300)
        frame.grid_propagate(False)
        # implement stretchability
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)
        # create a text widget
        self._console = tk.Text(frame, borderwidth=3, relief="sunken")
        self._console.config(font=("consolas", 12), undo=False, wrap='char')
        self._console.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)
        self._console.config(state="disabled")
        # create a scrollbar and associate it with txt
        scrollb = tk.Scrollbar(frame, command=self._console.yview)
        scrollb.grid(row=0, column=1, sticky='nsew')
        self._console['yscrollcommand'] = scrollb.set
        frame.pack(side="right", expand=True, fill="both")

    def _parse(self):
        """ button action:
            opens a open-file dialog box, reads the selected file and starts the send thread """
        self._pcap_file.set(fd.askopenfilename(filetypes=[('packet capture', '.pcap')]))
        self.console_print("parsing *.pcap file... ", end="")
        try:
            with open(self._pcap_file.get(), "rb") as f:
                # the pcap reader is split into two separate iterators
                # we use the second one to look ahead at the timestamp of
                # the next package to calculate the delay betwaeen the two
                readers = itertools.tee(dpkt.pcap.Reader(f))
                # offset the second iterator by one ahead
                try:
                    readers[1].__next__()  # Python 3.x
                except AttributeError:
                    readers[1].next()  # Python 2.x
                for ts, buf in readers[0]:
                    # since the second iterator is one step ahead it
                    # will throw an StopIteration exception
                    # but since the last package has none following
                    # we just set the last delay to 0
                    try:
                        try:
                            diff = readers[1].__next__()[0] - ts  # Python 3.x
                        except AttributeError:
                            diff = readers[1].next()[0] - ts  # Python 2.x
                    except StopIteration:
                        diff = 0
                    try:
                        self._pcap_list.append((diff, dpkt.ip.IP(buf)))
                    except dpkt.UnpackError as e:
                        print(e.message)
                    # print("{}: {}".format(ts, repr(dpkt.ip.IP(buf))))
            self.console_print("done", prompt="")
            # "press" the stop button to start thread
            self._stop()
        except IOError as e:
            if e.errno == 22:
                self._pcap_file.set("NO FILE SELECTED!")
                self._button_start.config(state="disabled")
                self._button_stop.config(state="disabled")
                self._button_pause.config(state="disabled")
                self._button_next.config(state="disabled")

    def _start(self):
        """ button action:
            start / continue sending packages """
        self._button_start.config(state="disabled")
        self._button_stop.config(state="normal")
        self._button_pause.config(state="normal")
        self._button_next.config(state="disabled")
        self._stop_event.clear()
        self._pause_event.clear()
        self._next_event.set()  # to continue when paused
        self._play_event.set()

    def _stop(self):
        """ button action:
            stop sending packages """
        self._button_start.config(state="normal")
        self._button_stop.config(state="disabled")
        self._button_pause.config(state="disabled")
        self._button_next.config(state="normal")
        self._play_event.clear()
        self._pause_event.clear()
        self._next_event.set()  # to continue when paused
        self._stop_event.set()
        # start the sending thread
        t = Thread(target=self._shoot, args=[self._pcap_list])
        t.start()
        # set/reset the progressbar
        self._progress_bar.config(value=0, maximum=len(self._pcap_list))
        self._progress_bar.update()

    def _pause(self):
        """ button action:
            pause sending packages """
        self._button_start.config(state="normal")
        self._button_stop.config(state="normal")
        self._button_pause.config(state="disabled")
        self._button_next.config(state="normal")
        self._play_event.clear()
        self._next_event.clear()
        self._pause_event.set()

    def _next(self):
        """ button action:
            send next package """
        self._button_start.config(state="normal")
        self._button_stop.config(state="normal")
        self._button_pause.config(state="disabled")
        self._button_next.config(state="normal")
        self._stop_event.clear()
        self._play_event.set()
        self._pause_event.set()
        self._next_event.set()

    def _shoot(self, pcap):
        """ send packages thread """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Internet, UDP
        # wait for start button press
        self._play_event.wait()
        for i, package in enumerate(pcap):
            # advance progress bar. the bar depends on the
            # total number of packages, not only the one sent.
            self._progress_bar.step()
            # skip packets before the start index
            # will raise an exception if the start index is ""
            # this happens if the user deletes the index -> ignore
            try:
                if i < self._start_index.get():
                    continue
            except (tk.TclError, ValueError):
                pass
            # pause thread
            if self._pause_event.is_set():
                self._next_event.wait()
                # in case the value has changed during pause
                try:
                    if i < self._start_index.get():
                        continue
                except (tk.TclError, ValueError):
                    pass
                self._next_event.clear()
            # stop thread
            if self._stop_event.is_set():
                break
            # current package
            ip = package[1]
            # only send udp packages
            if ip.p == dpkt.ip.IP_PROTO_UDP:
                # TODO handle invalid IPs
                # default ip
                dest = socket.inet_ntoa(ip.src)
                try:
                    if not self._dest_ip.get() == "":
                        dest = self._dest_ip.get()
                except (tk.TclError, ValueError):
                    pass
                #  default port
                port = ip.data.dport
                try:
                    if not self._dest_port.get() == 0:
                        port = self._dest_port.get()
                except (tk.TclError, ValueError):
                    pass
                # send package
                try:
                    sock.sendto(ip.data.data, (dest, port))
                except socket.gaierror as e:
                    self.console_print("invalid IP address")
                    self._pause()
                    continue
                except OverflowError as e:
                    self.console_print("port must be 0-65535")
                    self._pause()
                    continue
                # decode: get rid of the surrounding "'"s (just for python 3.x)
                data = codecs.encode(ip.data.data, 'hex_codec').decode()
                # decode and print data if checkbutton is set
                if self._decode.get():
                    self.console_print("#{}, dst: {}:{},\ndata: {}\ndecoded: {}".format(
                        i, dest, port, data, self.decode_data(ip.data.data, 16)), prompt="")
                else:
                    self.console_print("#{}, dst: {}:{},\ndata: {}".format(i, dest, port, data), prompt="")
            #
            sleep = package[0]
            try:
                if not self._shoot_wait.get() == 0:
                    sleep = self._shoot_wait.get()
            except (tk.TclError, ValueError):
                pass
            time.sleep(sleep)
        # "press" stop button if not already pressed
        if not self._stop_event.is_set():
            self._stop()
        self.console_print("finished!")

    def console_print(self, txt, prompt=">> ", end="\n"):
        """
        Prints the given txt to the console (text widget).

        :param txt: text to print
        :param prompt: console prompt, default: ">> "
        :param end: end character, default: "\n"
        """
        # make textbox writable
        self._console.config(state="normal")
        # built string and print it
        self._console.insert(tk.END, "{}{}{}".format(prompt, txt, end))
        # make textbox readonly again
        self._console.config(state="disabled")
        # scroll to the end
        self._console.see(tk.END)
        # update
        self.update_idletasks()

    def decode_data(self, data, block_size):
        """
        converts packed binary data to double
        this is a very specific case and serves merely as an example
        change this method to fit your requirements

        :param data: ip.data.data
        :param block_size: size of double representation in hex
        :return: list of doubles
        """
        # encode binary to get actual hex length
        encoded_data = codecs.encode(data, 'hex_codec')

        data_decoded = ""
        try:
            j = 0
            for i in range(0, len(encoded_data), block_size):
                # cut the desired section from the hex
                encoded_section = encoded_data[i:i + block_size]
                # get rid of the surrounding "'"s (just for python 3.x)
                decoded_section = encoded_section.decode()
                # convert back to binary string
                bytearray_section = bytearray.fromhex(decoded_section)
                # interpret bytes as packed binary data
                # the result is a little-endian (>) double (d)
                # unpack always returns a tuple containing one item -> [0]
                double = struct.unpack('>d', bytearray_section)[0]
                # map to names given in configfile concatenate formatted string
                data_decoded += self._decode_format.format(self._decode_mapping[j], double)
                j += 1
                # create data (old)
                # data_head = hex(struct.unpack('<Q', struct.pack('<d', i))[0])[2:18]
        except struct.error:
            data_decoded = "unknown encoding"
        finally:
            return data_decoded


if __name__ == '__main__':
    root = tk.Tk()
    PacketGun(root).pack(side="top", fill="both", expand=True)
    root.mainloop()
