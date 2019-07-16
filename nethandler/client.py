# -*- coding: utf-8 -*-
"""Client for network file handler."""
__author__ = "Sven Sager"
__copyright__ = "Copyright (C) 2019 Sven Sager"
__license__ = "GPLv3"
import socket
from pickle import dumps, loads
from threading import Thread, Event, Lock
from warnings import warn

from .helper import acheck

# Sync with server
SYS_SYNC = b'\x01\x06\x16\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x17'
# Disconnect cleanly
SYS_EXIT = b'\x01\x06\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x17'
# Get function list
SYS_FLST = b'\x01\x06L\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x17'


class CmdClient(Thread):

    """Network command client."""

    # TODO: __slots__ =

    def __init__(self, ip: str, port: int, timeout_ms=5000):
        """Init NetFH-class.
        :param ip: IP address of server
        :param port: Server port to connect to
        :param timeout_ms: Timeout value in milliseconds 100 - 65535
        """
        super().__init__()
        self.daemon = True

        self.__addr = ip
        self.__con = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__port = port
        self.__connected = None         # Socket connected and alive
        self.__sock_err = False         # Error value of socket
        self.__sock_lock = Lock()       # Socket lock on use
        self.__sock_run = Event()       # Event to trigger mainloop cycle
        self.__timeout = 0.0            # Socket timeout
        # TODO: Könnte Syncantwort auch Statusbits enthalten?
        self.__trigger = False          # Trigger to prevent to much sync commands
        self.__wait_reconnect = 0.1     # Timeout between reconnect attempts
        self.__wait_sync = 0.0          # Sync timer 45% of __timeout

        # Check parameters
        acheck(str, ip=ip)
        acheck(int, port=port)
        if not 0 < port <= 65535:
            raise ValueError(
                "parameter port must be in range 1 - 65535"
            )
        # Calculate values of timeout before connect
        self.__set_systimeout(timeout_ms)

    def __del__(self):
        """Close socket on del."""
        self.disconnect()

    def __getattr__(self, item):
        return lambda *args, **kwargs: self.call(item, *args, **kwargs)

    def __handle_response(self):
        rc = None

        check = self.__con.recv(16)
        if check[:3] == b'\x01\x06E':
            len_ex = int.from_bytes(check[3:7], byteorder="little")
            ex = loads(self.__con.recv(len_ex))
            raise ex

        elif check[:3] == b'\x01\x06O':
            len_rc = int.from_bytes(check[3:7], byteorder="little")
            if len_rc > 0:
                rc = loads(self.__con.recv(len_rc))

        # Set trigger
        self.__trigger = True

        return rc

    def __reconnect_socket(self):
        so = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        so.settimeout(self.__timeout)
        try:
            so.connect((self.__addr, self.__port))
        except Exception:
            so.close()
        else:
            # Close and remove old socket
            with self.__sock_lock:
                self.__con.close()
                self.__con = so
                self.__sock_err = False

            self.set_timeout(int(self.__timeout * 1000))

    def __set_systimeout(self, timeout_ms):
        """Class function to calculate timeout value.
        :param timeout_ms: Timeout value in milliseconds 100 - 65535
        """
        acheck(int, timeout_ms=timeout_ms)
        if 100 <= timeout_ms <= 65535:
            self.__timeout = timeout_ms / 1000

            # Set timeout on socket
            if self.__connected:
                self.__con.settimeout(self.__timeout)

            # Set wait of sync to 45 percent of timeout
            self.__wait_sync = self.__timeout / 10 * 4.5
            self.__sock_run.set()

        else:
            raise ValueError("value must between 10 and 65535 milliseconds")

    def _direct_send(self, send_bytes, recv_count):
        """Send bytes direct to server.

        :param send_bytes: Bytes to send to server
        :param recv_count: Receive this amount of bytes from server
        :returns: Received bytes
        """
        if not self.__connected:
            raise ValueError("I/O operation on closed file")

        with self.__sock_lock:
            self.__con.sendall(send_bytes)
            recv = self.__con.recv(recv_count)
            self.__trigger = True
            return recv

    def call(self, command: str, *args, **kwargs):
        """Call a function on command server.

        :param command: Command name on server
        :param args: Arguments to send
        :param kwargs: Keyword arguments to send
        """
        if not self.__connected:
            raise ValueError("I/O operation on closed socket")

        acheck(str, command=command)
        rc = None

        b_command = command.encode("ASCII")
        b_args = b'' if len(args) == 0 else dumps(args)
        b_kwargs = b'' if len(kwargs) == 0 else dumps(kwargs)

        # bAAiiii00000000b = 16
        with self.__sock_lock:
            self.__con.send(
                b'\x01\x06F' +
                len(b_command).to_bytes(length=4, byteorder="little") +
                len(b_args).to_bytes(length=4, byteorder="little") +
                len(b_kwargs).to_bytes(length=4, byteorder="little") +
                b'\x17'
            )
            self.__handle_response()

            self.__con.sendall(b_command + b_args + b_kwargs)
            self.__handle_response()

        return rc

    def connect(self):
        """Connect to server and start processing commands."""
        self.start()

    def disconnect(self):
        """Close connection to server."""
        if not self.__connected:
            return

        # Exit mainloop
        self.__connected = False
        self.__sock_run.set()

        # Send a clean disconnect to server
        with self.__sock_lock:
            try:
                self.__con.send(SYS_EXIT)
            except Exception:
                pass

        self.__con.close()

    def get_timeout(self):
        """Get timeout value.
        :return: Timeout in milliseconds
        """
        return int(self.__timeout * 1000)

    def get_functions(self):
        if not self.__connected:
            raise ValueError("I/O operation on closed socket")

        with self.__sock_lock:
            self.__con.send(SYS_FLST)
            return self.__handle_response()

    def run(self):
        """Check connection state and hold connection."""
        while self.__connected:
            self.__sock_run.clear()

            # On error event create a new connection
            if self.__sock_err:
                self.__wait_sync = self.__wait_reconnect
                self.__reconnect_socket()

            else:
                # Do a sync if socket is idling
                if not self.__trigger and \
                        self.__sock_lock.acquire(blocking=False):
                    try:
                        self.__con.send(SYS_SYNC)
                        check = self.__handle_response()
                    except Exception as e:
                        warn(e, RuntimeWarning)
                        self.__sock_err = True
                        self.__sock_run.set()

                    self.__sock_lock.release()

                self.__trigger = False

            self.__sock_run.wait(self.__wait_sync)

    def start(self):
        """Connect to server and start processing commands."""
        if self.__connected is not None:
            raise RuntimeError("clients can only be connected once")

        so = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        so.settimeout(self.__timeout)
        so.connect((self.__addr, self.__port))
        self.__con = so

        self.__connected = True
        self.set_timeout(int(self.__timeout * 1000))
        super().start()

    def set_timeout(self, timeout_ms: int):
        """Set connection timeout.
        :param timeout_ms: Timeout in milliseconds
        """
        if not self.__connected:
            raise ValueError("I/O operation on closed socket")
        acheck(int, timeout_ms=timeout_ms)

        self.__set_systimeout(timeout_ms)

        with self.__sock_lock:
            self.__con.send(
                b'\x01\x06C' +
                timeout_ms.to_bytes(length=2, byteorder="little") +
                b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x17'
            )
            self.__handle_response()

    @property
    def connected(self):
        return self.__connected

    timeout = property(get_timeout, set_timeout)
