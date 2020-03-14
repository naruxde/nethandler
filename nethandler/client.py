# -*- coding: utf-8 -*-
"""Client for network file handler."""
__author__ = "Sven Sager"
__copyright__ = "Copyright (C) 2019 Sven Sager"
__license__ = "GPLv3"

from pickle import dumps, loads
from socket import error as socketerror
from struct import pack, unpack
from threading import Event, Lock, Thread

from .helper import HEADER_START, HEADER_STOP, HandlerSocket, acheck

# Sync with server
SYS_SYNC = b'\x01\x06\x16\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x17'
# Disconnect cleanly
SYS_EXIT = b'\x01\x06\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x17'
# Get function list
SYS_FLST = b'\x01\x06L\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x17'


class CallSave:
    """Handle return values of call_save method."""
    __slots__ = "value", "success"

    def __init__(self, success: bool, value: object):
        self.value = value
        self.success = success

    def __bool__(self) -> bool:
        return self.success


# FIXME: Start own thread inside of this class
class CmdClient(Thread):
    """Network command client."""

    # TODO: __slots__ =

    def __init__(self, server: str, port: int, timeout_ms=5000):
        """
        Init CmdClient-class.

        :param server: Address of server
        :param port: Server port to connect to
        :param timeout_ms: Timeout value in milliseconds 10 - 4294967295
        """
        super().__init__()
        self.daemon = True

        self.__addr = server
        self.__con = HandlerSocket()
        self.__port = port
        self.__connected = None  # Socket connected and alive
        self.__sock_err = False  # Error value of socket
        self.__sock_lock = Lock()  # Socket lock on use
        self.__sock_run = Event()  # Event to trigger mainloop cycle
        self.__timeout = 0.0  # Socket timeout
        self.__wait_reconnect = 0.1  # Timeout between reconnect attempts
        self.__wait_sync = 0.0  # Sync timer 45% of __timeout

        # Check parameters
        acheck(str, server=server)
        acheck(int, port=port)
        if not 0 < port <= 65535:
            raise ValueError("parameter port must be in range 1 - 65535")

        # Calculate values of timeout before connect
        self.__set_systimeout(timeout_ms)

    def __del__(self) -> None:
        """Close socket on del."""
        self.disconnect()

    def __getattr__(self, item):
        """
        Handle function names from server as local functions of this class.

        :param item: Function name
        :return: Return value of server function
        """
        return lambda *args, **kwargs: self.call(item, *args, **kwargs)

    def __handle_response(self):
        """
        Server answer manager.

        This function will process the server answer and returns a python
        object. An exception will be raised, if the server function threw one.

        :return: Python object from server
        """
        ex = None
        rc = None

        net_cmd = self.__con.recvall(16)
        p_start, cmd, payload_length, blob, p_end = unpack("<s2sI8ss", net_cmd)

        # Check received net command or disconnect
        if not (p_start == HEADER_START and p_end == HEADER_STOP):
            raise RuntimeError("net cmd not valid {0}".format(net_cmd))

        if cmd == b'\x06E':
            # Server reports an exception
            b_ex = self.__con.recvall(payload_length)
            ex = loads(b_ex)

        elif cmd == b'\x06O':
            # Server returns python object as bytes
            if payload_length > 0:
                b_rc = self.__con.recvall(payload_length)
                rc = loads(b_rc)

        if ex is not None:
            raise ex
        return rc

    def __set_systimeout(self, timeout_ms):
        """
        Class function to calculate timeout value.

        Set timeout in class and on server. This function is not locking
        socket, so it must be used in locked environments. Never raise
        exceptions (expect wrong call parameters).

        :param timeout_ms: Timeout value in milliseconds 10 - 4294967295
        """
        acheck(int, timeout_ms=timeout_ms)
        if not 10 <= timeout_ms <= 4294967295:
            raise ValueError("value must between 10 and 4294967295 milliseconds")

        self.__timeout = timeout_ms / 1000

        # Set timeout on socket
        if self.__connected:
            self.__con.settimeout(self.__timeout)
            try:
                self.__con.sendall(pack(
                    "<s2sI8xs",
                    HEADER_START, b'\x06C', timeout_ms, HEADER_STOP
                ))
                self.__handle_response()
            except Exception:
                self.__sock_err = True

        # Set wait of sync to 45 percent of timeout
        self.__wait_sync = self.__timeout / 100 * 45
        self.__sock_run.set()

    def _direct_send(self, send_bytes, recv_count) -> bytes:
        """
        Send bytes direct to server.

        :param send_bytes: Bytes to send to server
        :param recv_count: Receive this amount of bytes from server
        :returns: Received bytes
        """
        if not self.__connected:
            raise ValueError("I/O operation on closed file")

        with self.__sock_lock:
            try:
                self.__con.sendall(send_bytes)
                recv = self.__con.recvall(recv_count)
                return recv

            except Exception:
                self.__sock_err = True
                self.__sock_run.set()
                raise

    def call(self, command: str, *args, **kwargs):
        """
        Call a function on command server.

        :param command: Command name on server
        :param args: Arguments to send
        :param kwargs: Keyword arguments to send
        :return: Python object from server
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
                self.__con.sendall(pack(
                    "<s2sIIIs",
                    HEADER_START, b'\x06F', len(b_command), len(b_args), len(b_kwargs), HEADER_STOP
                ))
                self.__handle_response()

                self.__con.sendall(b_command + b_args + b_kwargs)
                rc = self.__handle_response()

            except socketerror:
                self.__sock_err = True
                self.__sock_run.set()
                raise
            except Exception:
                raise

        return rc

    def call_save(self, command: str, *args, **kwargs) -> CallSave:
        """
        Call a function on command server without raising an exception.

        This function returns an <class 'CallSave'> object. If the success
        status is True, the value will be the returned value, if False
        the exception is put to value property.

        :param command: Command name on server
        :param args: Arguments to send
        :param kwargs: Keyword arguments to send
        :return: CallSave object with returned value or an exception
        """
        try:
            return CallSave(True, self.call(command, *args, **kwargs))
        except Exception as e:
            return CallSave(False, e)

    def connect(self):
        """Connect to server and start processing commands."""
        self.start()

    def connect_async(self):
        """Connect to server in background."""
        self.start(connect_async=True)

    def disconnect(self):
        """Close connection to server."""
        if not self.__connected:
            return

        # Exit mainloop
        self.__connected = False
        self.__sock_run.set()

        # Send a clean disconnect to server
        # TODO: Should we set a time out to avoid a dead lock?
        with self.__sock_lock:
            try:
                self.__con.sendall(SYS_EXIT)
            except Exception:
                pass

        self.__con.close()

    def get_functions(self) -> list:
        """
        Get a list of all functions available on the server.

        :return: List with function names as <class 'str'>
        """
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

            # On error event, create a new connection
            if self.__sock_err:
                so = HandlerSocket()
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
            if self.__sock_lock.acquire(blocking=False):
                try:
                    # Send data
                    self.__con.sendall(SYS_SYNC)

                    # Receive data
                    self.__handle_response()
                except Exception:
                    # TODO: Show this as RuntimeWarning?
                    self.__sock_err = True
                    self.__sock_run.set()

                self.__sock_lock.release()

            self.__sock_run.wait(self.__wait_sync)

    def start(self, connect_async=False):
        """
        Connect to server and start processing commands.

        :param connect_async: Start handling, even server ist unreachable
        """
        if self.__connected is not None:
            raise RuntimeError("client instances can only be connected once")

        if connect_async:
            self.__connected = True
            self.__sock_err = True
        else:
            so = HandlerSocket()
            so.settimeout(self.__timeout)
            so.connect((self.__addr, self.__port))
            self.__con = so

            self.__connected = True
            self.timeout = int(self.__timeout * 1000)

        # Start thread mainloop
        super().start()

    @property
    def connected(self):
        """
        Get status whether connection is able to handle calls

        :return: True, if connection is open
        """
        return self.__connected

    @property
    def port(self) -> int:
        """
        Get port number of connection.

        :return: Port number of connection
        """
        return self.__port

    @property
    def reconnecting(self) -> bool:
        """
        Get status of a reconnect after network failure.

        :return: True, if module is reconnecting to server
        """
        return self.__sock_err

    @property
    def server(self) -> str:
        """
        Get server address of connection.

        :return: Server address of connection
        """
        return self.__addr

    @property
    def timeout(self) -> int:
        """
        Get timeout value of connection.

        :return: Timeout in milliseconds
        """
        return int(self.__timeout * 1000)

    @timeout.setter
    def timeout(self, timeout_ms: int) -> None:
        """
        Set timeout for connection.

        :param timeout_ms: Timeout in milliseconds
        """
        if not self.__connected:
            raise ValueError("I/O operation on closed socket")
        acheck(int, timeout_ms=timeout_ms)

        with self.__sock_lock:
            self.__set_systimeout(timeout_ms)
