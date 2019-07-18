# -*- coding: utf-8 -*-
"""Client for network file handler."""
__author__ = "Sven Sager"
__copyright__ = "Copyright (C) 2019 Sven Sager"
__license__ = "GPLv3"
import socket
from pickle import dumps, loads
from struct import pack, unpack
from threading import Thread, Event, Lock
from warnings import warn

from .helper import acheck, recv_data

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

        net_cmd = self.__con.recv(16)
        p_start, cmd, payload_length, blob, p_end = unpack("<s2sI8ss", net_cmd)

        # Check received net command or disconnect
        if not (p_start == b'\x01' and p_end == b'\x17'):
            raise RuntimeError("net cmd not valid {0}".format(net_cmd))

        if cmd == b'\x06E':
            b_ex = recv_data(self.__con, payload_length)
            ex = loads(b_ex)
            raise ex

        elif cmd == b'\x06O':
            if payload_length > 0:
                b_rc = recv_data(self.__con, payload_length)
                rc = loads(b_rc)

        # Set trigger
        self.__trigger = True

        return rc

    def __set_systimeout(self, timeout_ms):
        """Class function to calculate timeout value.

        Set timeout in class and on server (NOT LOCKED).

        :param timeout_ms: Timeout value in milliseconds 100 - 65535
        """
        acheck(int, timeout_ms=timeout_ms)
        if not 100 <= timeout_ms <= 65535:
            raise ValueError("value must between 10 and 65535 milliseconds")

        self.__timeout = timeout_ms / 1000

        # Set timeout on socket
        if self.__connected:
            self.__con.settimeout(self.__timeout)
            try:
                self.__con.sendall(
                    b'\x01\x06C' +
                    pack("<H10s", timeout_ms, b'\x00' * 10) +
                    b'\x17'
                )
                self.__handle_response()
            except Exception:
                self.__sock_err = True

        # Set wait of sync to 45 percent of timeout
        self.__wait_sync = self.__timeout / 10 * 4.5
        self.__sock_run.set()

    def _direct_send(self, send_bytes, recv_count):
        """Send bytes direct to server.

        :param send_bytes: Bytes to send to server
        :param recv_count: Receive this amount of bytes from server
        :returns: Received bytes
        """
        if not self.__connected:
            raise ValueError("I/O operation on closed file")

        with self.__sock_lock:
            try:
                self.__con.sendall(send_bytes)
                recv = self.__con.recv(recv_count)
                self.__trigger = True
                return recv

            except Exception:
                self.__sock_err = True
                self.__sock_run.set()
                raise

    def call(self, command: str, *args, **kwargs):
        """Call a function on command server.

        :param command: Command name on server
        :param args: Arguments to send
        :param kwargs: Keyword arguments to send
        """
        if not self.__connected:
            raise ValueError("I/O operation on closed socket")

        acheck(str, command=command)
        if len(command) > 255:
            raise ValueError("command supports max 255 signs")

        b_command = command.encode("ASCII")
        b_args = b'' if len(args) == 0 else dumps(args)
        b_kwargs = b'' if len(kwargs) == 0 else dumps(kwargs)

        # bCMcaaaakkkk000b = 16
        with self.__sock_lock:
            try:
                self.__con.sendall(
                    b'\x01\x06F' +
                    pack("<BII3s", len(b_command), len(b_args), len(b_kwargs), b'\x00' * 3) +
                    b'\x17'
                )
                self.__handle_response()

                self.__con.sendall(b_command + b_args + b_kwargs)
                rc = self.__handle_response()

            except Exception:
                self.__sock_err = True
                self.__sock_run.set()
                raise

        return rc

    def connect(self):
        """Connect to server and start processing commands."""
        self.start()

    def connect_async(self):
        self.start(connect_async=True)

    def disconnect(self):
        """Close connection to server."""
        if not self.__connected:
            return

        # Exit mainloop
        self.__connected = False
        self.__sock_run.set()

        # Send a clean disconnect to server
        # TODO: Timeout für Socklock, damit es weiter geht?
        with self.__sock_lock:
            try:
                self.__con.sendall(SYS_EXIT)
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
            try:
                self.__con.sendall(SYS_FLST)
                return self.__handle_response()

            except Exception:
                self.__sock_err = True
                self.__sock_run.set()
                raise

    def run(self):
        """Check connection state and hold connection."""
        while self.__connected:
            self.__sock_run.clear()

            # On error event create a new connection
            if self.__sock_err:
                so = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                so.settimeout(self.__timeout)
                try:
                    so.connect((self.__addr, self.__port))
                except Exception:
                    so.close()
                    self.__sock_run.wait(self.__wait_reconnect)
                    continue

                # Close and remove old socket
                with self.__sock_lock:
                    self.__con.close()
                    self.__con = so
                    self.__sock_err = False

                    # Set timeout on server
                    self.__set_systimeout(int(self.__timeout * 1000))
                    if self.__sock_err:
                        continue

            # Do a sync if socket is idling
            if not self.__trigger and \
                    self.__sock_lock.acquire(blocking=False):

                try:
                    # Send data
                    self.__con.sendall(SYS_SYNC)

                    # Receive data
                    self.__handle_response()
                except Exception:
                    # ERROR: warn(e, RuntimeWarning)
                    self.__sock_err = True
                    self.__sock_run.set()

                self.__sock_lock.release()

            self.__trigger = False
            self.__sock_run.wait(self.__wait_sync)

    def start(self, connect_async=False):
        """Connect to server and start processing commands.

        :param connect_async: Start handling, even server ist unreachable
        """
        if self.__connected is not None:
            raise RuntimeError("client instances can only be connected once")

        if connect_async:
            self.__connected = True
            self.__sock_err = True
        else:
            so = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            so.settimeout(self.__timeout)
            so.connect((self.__addr, self.__port))
            self.__con = so

            self.__connected = True
            self.set_timeout(int(self.__timeout * 1000))

        # Start thread mainloop
        super().start()

    def set_timeout(self, timeout_ms: int):
        """Set connection timeout.
        :param timeout_ms: Timeout in milliseconds
        """
        if not self.__connected:
            raise ValueError("I/O operation on closed socket")
        acheck(int, timeout_ms=timeout_ms)

        with self.__sock_lock:
            self.__set_systimeout(timeout_ms)

    @property
    def connected(self):
        return self.__connected

    timeout = property(get_timeout, set_timeout)
