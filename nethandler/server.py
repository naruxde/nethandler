# -*- coding: utf-8 -*-
"""Server for network file handler."""
__author__ = "Sven Sager"
__copyright__ = "Copyright (C) 2020 Sven Sager"
__license__ = "GPLv3"

import struct
from enum import Enum
from hashlib import sha256
from inspect import getmembers, ismethod
from logging import getLogger
from pickle import dumps, loads
from socket import SHUT_RDWR
from threading import Event, Thread
from time import time

from .acl import AclBase
from .helper import HEADER_START, HEADER_STOP, HandlerSocket, acheck

log = getLogger()


class _RegisterType(Enum):
    """Register types for cmd functions."""

    USER = "user"
    AUTH = "auth"
    CONNECT = "connect"
    DISCONNECT = "disconnect"


class CmdClientInfo:
    """Information of connected client."""
    __slots__ = "connected_since", "acl", "data", "ip", "is_auth", "port"

    def __init__(self, ip: str, port: int, acl: int, connected_since: float, is_auth: bool, data) -> None:
        self.acl = acl
        self.connected_since = connected_since
        self.data = data
        self.ip = ip
        self.is_auth = is_auth
        self.port = port

    def __str__(self) -> str:
        """
        Get client ip address for class string.

        :return: Client ip address
        """
        return self.ip

    @property
    def connection_time(self) -> float:
        """
        Get connection time of this client since connection established.

        :return: Time since established connection
        """
        return time() - self.connected_since


class CmdHandler:
    """
    Default cmd handler for CmdServer class.

    Users can inherit from this class the base functionality and should
    override the existing methods.
    """

    def auth(self, client: CmdClientInfo, username: str) -> str:
        """
        Server will call this function on auth request from client.

        You have to check the given username and return the password
        as return value in this function. The server will check the
        value und will set 'is_auth' to True in the CmdClientInfo
        object.

        :param client: Remote client information
        :param username: Given username from the client request
        :return: The right password as string or empty string to reject
        """
        return ""

    def connect(self, client: CmdClientInfo) -> bool:
        """
        A new client is connected to the server.

        :param client: Remote client information
        :return: True to accept the connection, False to reject the client
        """
        return True

    def disconnect(self, client: CmdClientInfo, clean: bool) -> None:
        """
        A client disconnects from the server.

        :param client: Remote client information
        :param clean: True, if client send disconnect request, False on failure
        """
        pass


class CmdServer(Thread):
    """Network command server."""

    def __init__(self, ip_acl: AclBase, port: int, bind_ip="", cmd_handler=None):
        acheck(AclBase, ip_acl=ip_acl)
        acheck(int, port=port)
        acheck(str, bind_ip=bind_ip)
        acheck(type, cmd_handler_noneok=cmd_handler)
        if not 0 < port <= 65535:
            raise ValueError("parameter port must be in range 1 - 65535")

        super().__init__()

        self.__ip_acl = ip_acl
        self._bind_ip = bind_ip
        self._cmd_handler = CmdHandler if not cmd_handler else cmd_handler  # type: type
        self._cmd_handler_locked = cmd_handler is not None
        self._data = None
        self._port = port
        self._evt_exit = Event()
        self._so = HandlerSocket()
        self._th_clients = []

    def __register_function(self, register: _RegisterType, function: type, name="") -> None:
        """
        Manager to register functions of public register calls.

        :param register: Type of registration
        :param function: Function to register
        :param name: Alternative name for client call
        """
        if self.is_alive():
            raise RuntimeError("can not register functions after server start")
        if self._cmd_handler_locked:
            raise RuntimeError("can not add functions to inherited cmd handler")
        if not callable(function):
            raise RuntimeError("function ist not callable")

        if register == _RegisterType.USER:
            setattr(self._cmd_handler, name or function.__name__, function)
        else:
            setattr(self._cmd_handler, register.value, function)

    def change_acl(self, new_acl: AclBase) -> None:
        """
        Change ip acl and check all connected clients.

        The new acl will set to this server and will be applied to new
        connections. All existing connections will be checked and set to
        new alc levels or disconnected if they are not allowed.

        :param new_acl: New ACLs vor this server
        """
        acheck(AclBase, new_acl=new_acl)
        self.__ip_acl = new_acl

        for client in self._th_clients:  # type: CmdConnection
            acl_level = self.__ip_acl.get_level(client.address)
            if not acl_level:
                # Disconnect client, because it is not in new ACLs
                log.warning("client {0} removed from acl - disconnect!".format(client.address))
                client.stop()

            elif acl_level != client._acl:
                # Patch acl level in client thread
                log.warning(
                    "change acl level from {0} to {1} on existing "
                    "connection {2}".format(acl_level, client._acl, client.address)
                )
                client._acl = acl_level

    def register(self, function, name="") -> None:
        """
        Register a new function to server which can be called from clients.

        The name of the function will be the same, which the clients have
        to use. You can change the name for clients with the name parameter.

        :param function: Function to register
        :param name: Alternative function name for clients
        """
        self.__register_function(_RegisterType.USER, function, name)

    def register_auth(self, function) -> None:
        """
        Register a auth function for user management.

        This function will be called, when a client calls the auth method
        to authenticate against your server. The function must support
        arguments for <class 'CmdClientInfo'> and username. You have to return
        the password as <class 'str'> which will check form the server against
        the sent hashed password form the client. If the password matches, the
        CmdClientInfo.is_auth method will return True on all function calls.

        Empty passwords are not allowed!

        def auth(self, client: CmdClientInfo, username: str) -> str

        :param function: Function to call on client auth request
        """
        self.__register_function(_RegisterType.AUTH, function)

    def register_connect(self, function) -> None:
        """
        Register a connect function for new client connections.

        This function will be called, when a new client connects to the
        server. It must support an argument for <class 'CmdClientInfo'> and
        has to return True. This can be used to check acl level or check IP
        addresses and deny connection by returning False.

        def connect(self, client: CmdClientInfo) -> bool

        :param function: Function to call on client connect
        """
        self.__register_function(_RegisterType.CONNECT, function)

    def register_disconnect(self, function) -> None:
        """
        Register a disconnect function if client disconnects.

        This function will be called, when a client disconnects from the
        server. It must support am argument for <class 'CmdClientInfo'> and
        <class 'bool'> which is True, if the client request the disconnection
        and will be False, if the client had a network failure.

        def disconnect(self, client: CmdClientInfo, clean: bool) -> None

        :param function: Function to call on client disconnect
        """
        self.__register_function(_RegisterType.DISCONNECT, function)

    def run(self) -> None:
        """Start server to accept connections and handle them."""
        log.debug("enter CmdServer.run()")

        # Open socket and wait until it works
        while not self._evt_exit.is_set():
            try:
                self._so.bind((self._bind_ip, self._port))
            except Exception as e:
                log.warning("can not bind socket: {0} - retry".format(e))
                self._evt_exit.wait(1)
            else:
                self._so.listen(16)
                break

        # Start working with opened socket
        while not self._evt_exit.is_set():

            # Wait for a client connection
            log.info("Wait for new connection")
            try:
                client_sock, client_address = self._so.accept()
                client_address, client_port = client_address
            except Exception as e:
                if not self._evt_exit.is_set():
                    log.exception(e)
                continue

            # Check ACL
            acl_level = self.__ip_acl.get_level(client_address)
            if acl_level:
                # Start client thread
                th = CmdConnection(client_sock, acl_level, self._cmd_handler)
                th.set_data_object(self._data)
                th.start()
                self._th_clients.append(th)
            else:
                client_sock.close()
                log.warning(
                    "Host ip '{0}' does not match any acl entry - disconnect"
                    "".format(client_address)
                )

            # Clean up thread list of dead ones
            self._th_clients = [
                th_check for th_check in self._th_clients if th_check.is_alive()
            ]

        # Disconnect all clients
        for th in self._th_clients:
            th.stop()

        # Close socket
        self._so.close()
        self._so = None

        log.debug("leave CmdServer.run()")

    def stop(self) -> None:
        """Close all connections and sockets."""
        log.debug("enter CmdServer.stop()")

        self._evt_exit.set()
        if self._so is not None:
            try:
                # Free from accept function to prevent new connections
                self._so.shutdown(SHUT_RDWR)
            except Exception as e:
                log.exception(e)

        # Thread will disconnect all clients on the end of mainloop
        self.join(timeout=3)

        log.debug("leave CmdServer.stop()")

    @property
    def data(self):
        """Get data object which is accessible through CmdClientInfo."""
        return self._data

    @data.setter
    def data(self, value) -> None:
        """Set data object which is accessible through CmdClientInfo."""
        self._data = value
        for th in self._th_clients:
            th.set_data_object(self._data)


class CmdConnection(Thread):
    """Handle connection to client and do the jobs."""

    def __init__(self, client_socket: HandlerSocket, acl_level: int, cmd_handler: type, timeout=5.0):
        """
        Init CmdHandler class.

        :param client_socket: Socket of client connection
        :param acl_level: Access level for this connection
        :param timeout: Timeout of socket connection
        """
        super().__init__()
        self.__acl = acl_level
        self.__cmd = cmd_handler()
        self.__con = client_socket
        self.__connected = True
        self.__connected_since = time()
        self.__data = None
        self.__evt_exit = Event()
        self.__is_auth = False
        self.__timeout = timeout

        self.__addr, self.__port = client_socket.getpeername()

        # Set default timeout to socket
        self.__con.settimeout(self.__timeout)

    def __handle_exception(self, ex: Exception) -> None:
        """
        Internal method to send exceptions to clients.

        :param ex: Exception to send to client
        """
        log.exception(ex)

        # Send exception to client
        b_ex = dumps(ex)
        self.__con.sendall(struct.pack(
            "<s2sI8xs",
            HEADER_START, b'\x06E', len(b_ex), HEADER_STOP
        ) + b_ex)

    def __handle_response(self, cmd=b'\x06O', blob=b'', payload=b'') -> None:
        """
        Internal method to send response to client.

        :param cmd: Command bytes for client (cmd / 2 bytes)
        :param blob: Blob in cmd message for free use (blob / 8 bytes)
        :param payload: Optional payload to send
        """
        do_log = len(payload) > 0
        if do_log:
            log.debug(
                "enter __handle_response cmd={0}, payload_length={1}"
                "".format(cmd, len(payload))
            )

        if blob:
            self.__con.sendall(struct.pack(
                "<s2sI8ss",
                HEADER_START, cmd, len(payload), blob, HEADER_STOP
            ) + payload)
        else:
            self.__con.sendall(struct.pack(
                "<s2sI8xs",
                HEADER_START, cmd, len(payload), HEADER_STOP
            ) + payload)

        if do_log:
            log.debug(
                "leave __handle_response cmd={0} payload_length={1}"
                "".format(cmd, len(payload))
            )

    def set_data_object(self, data):
        """Set the data object for client info of this connection."""
        self.__data = data

    def run(self):
        """Execute the requests of client."""
        log.debug("enter CmdHandler.run()")
        log.info("got new connection from host {0} with acl {1}".format(self.__addr, self.__acl))

        # Starting connection handling
        try:
            # Call user function for connect event
            client = CmdClientInfo(
                self.__addr, self.__port,
                self.__acl, self.__connected_since, self.__is_auth,
                self.__data,
            )
            if self.__cmd.connect(client) is False:
                log.warning("connect function does not return True - disconnect")
                self.__evt_exit.set()
        except Exception as e:
            log.exception(e)
            self.__evt_exit.set()

        clean = False
        while not self.__evt_exit.is_set():
            # Start calculating runtime
            ot = time()

            # Receive full command or disconnect
            try:
                # b CM IIII 00000000 b = 16
                net_cmd = self.__con.recvall(16, self.__evt_exit)

                # Unpack the bytes to process
                p_start, cmd, payload_length, blob, p_stop = struct.unpack("<s2sI8ss", net_cmd)
            except Exception as e:
                log.exception(e)
                break

            # Check received net command or disconnect
            if not (p_start == HEADER_START and p_stop == HEADER_STOP):
                log.error("net cmd not valid {0}".format(net_cmd))
                break

            if cmd == b'\x06\x16':
                # Synchronization in idle to reset timeout
                self.__handle_response()

            elif cmd == b'\x06A':
                # Authenticate request from client
                # b CM IIII c0000000 b = 16

                action, = struct.unpack("<?7x", blob)
                if action:
                    # Authenticate client
                    try:
                        buff = self.__con.recvall(payload_length, self.__evt_exit)
                        password_hash = buff[:32]
                        username = buff[32:].decode("utf-8")

                        password = self.__cmd.auth(CmdClientInfo(
                            self.__addr, self.__port,
                            self.__acl, self.__connected_since, self.__is_auth,
                            self.__data,
                        ), username)
                    except Exception as e:
                        self.__handle_exception(e)
                        continue

                    # Empty passwords are not allowed and return False
                    if password:
                        password = sha256(password.encode("utf-8")).digest()
                    self.__is_auth = password_hash == password

                else:
                    # Delete auth token from client
                    self.__is_auth = False

                self.__handle_response(
                    cmd=cmd,
                    blob=struct.pack("<?7x", self.__is_auth)
                )

                log.info("set is_auth of client '{0}' to {1}".format(
                    self.__addr, self.__is_auth
                ))

            elif cmd == b'\x06C':
                # Configure socket on client demand
                # b CM IIII 00000000 b = 16

                self.__timeout = payload_length / 1000
                self.__con.settimeout(self.__timeout)
                log.debug("set socket timeout to {0}".format(self.__timeout))

                self.__handle_response()

                # Do not calculate runtime on the end of this while
                continue

            elif cmd == b'\x06F':
                # Call a function of CmdHandler
                # bCM IIII aaaakkkk b = 16
                try:
                    len_args, len_kwargs = struct.unpack("<II", blob)
                except Exception as e:
                    self.__handle_exception(e)
                    continue

                # Command parsed successfully
                self.__handle_response()

                # Process payload
                try:
                    b_command = self.__con.recvall(payload_length, self.__evt_exit)
                    b_args = self.__con.recvall(len_args, self.__evt_exit)
                    b_kwargs = self.__con.recvall(len_kwargs, self.__evt_exit)

                    command = b_command.decode("ASCII")
                    args = () if len_args == 0 else loads(b_args)
                    kwargs = {} if len_kwargs == 0 else loads(b_kwargs)

                    # User can not call auth, connect or disconnect method
                    if command in ("auth", "unauth", "connect", "disconnect"):
                        raise AttributeError(
                            "'{0}' object has no attribute '{1}'"
                            "".format(self.__cmd.__class__.__name__, command)
                        )

                    func = getattr(self.__cmd, command)
                    rc = func(
                        CmdClientInfo(
                            self.__addr, self.__port,
                            self.__acl, self.__connected_since, self.__is_auth,
                            self.__data,
                        ),
                        *args,
                        **kwargs
                    )

                except Exception as e:
                    self.__handle_exception(e)
                else:
                    if rc is None:
                        self.__handle_response()
                    else:
                        b_rc = dumps(rc)
                        self.__handle_response(payload=b_rc)

            elif cmd == b'\x06L':
                # Get function list of handler
                lst = []
                for name, method in getmembers(self.__cmd, ismethod):  # type: str, method
                    if name.find("_") != 0:
                        lst.append(name)
                self.__handle_response(payload=dumps(lst))

            elif cmd == b'\x06\x04':
                # End of transmission
                clean = True
                self.__evt_exit.set()
                continue

            else:
                # No supported command - disconnect
                log.error("found unknown net cmd: {0}".format(cmd))
                break

            # Calculate process time
            com_time = time() - ot
            if com_time > self.__timeout:
                log.warning("runtime more than timeout of {0} ms: {1}!".format(
                    int(self.__timeout * 1000), int(com_time * 1000)
                ))

        # Call clean up function
        try:
            self.__cmd.disconnect(CmdClientInfo(
                self.__addr, self.__port,
                self.__acl, self.__connected_since, self.__is_auth,
                self.__data,
            ), clean)
            if not clean:
                log.error("dirty shutdown of connection")
        except Exception as e:
            log.exception(e)

        self.__connected = False
        self.__con.close()

        log.info("disconnected from {0}".format(self.__addr))
        log.debug("leave RevPiSlaveDev.run()")

    def stop(self) -> None:
        """Quit command executing of mainloop and exit."""
        log.debug("enter CmdHandler.stop()")

        self.__evt_exit.set()
        if self.__connected:
            self.__con.shutdown(SHUT_RDWR)

        log.debug("leave CmdHandler.stop()")

    @property
    def address(self) -> str:
        """Get client IP address."""
        return self.__addr

    @property
    def connected(self) -> bool:
        """Get status of client is connected."""
        return self.__connected

    @property
    def port(self) -> int:
        """Get client port of connection."""
        return self.__port
