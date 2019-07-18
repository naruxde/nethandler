# -*- coding: utf-8 -*-
"""Server for network file handler."""
__author__ = "Sven Sager"
__copyright__ = "Copyright (C) 2019 Sven Sager"
__license__ = "GPLv3"
import socket
import struct
from enum import Enum
from logging import getLogger
from pickle import dumps, loads
from threading import Event, Thread
from time import time

from .acl import AclBase
from .helper import CmdClient, acheck, recv_data

log = getLogger()


class RegisterType(Enum):
    USER = "user"
    CONNECT = "connect"
    DISCONNECT = "disconnect"


class CmdHandler:

    def connect(self, client: CmdClient):
        return True

    def disconnect(self, client: CmdClient, clean: bool):
        pass


class CmdServer(Thread):

    """Network command server."""

    def __init__(self, ip_acl: AclBase, port: int, bind_ip="", cmd_handler=None):
        acheck(AclBase, ip_acl=ip_acl)
        acheck(int, port=port)
        acheck(str, bind_ip=bind_ip)
        acheck(type, cmd_handler_noneok=cmd_handler)
        if not 0 < port <= 65535:
            raise ValueError(
                "parameter port must be in range 1 - 65535"
            )

        super().__init__()

        self.__ip_acl = ip_acl
        self._bind_ip = bind_ip
        self._cmd_handler = CmdHandler if not cmd_handler else cmd_handler  # type: type
        self._port = port
        self._evt_exit = Event()
        self._exitcode = -1
        self._so = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._th_clients = []

    def __register_function(self, register: RegisterType, function: type, name=""):
        if self.is_alive():
            raise RuntimeError("can not register functions after server start")
        if not type(self._cmd_handler) != CmdHandler:
            raise RuntimeError("can not add functions to inherited cmd handler")
        if not callable(function):
            raise  RuntimeError("function ist not callable")

        if register == RegisterType.USER:
            if not name:
                name = function.__name__
            setattr(self._cmd_handler, name, function)
        else:
            setattr(self._cmd_handler, register.value, function)

    def change_acl(self, new_acl: AclBase):
        """Change ip acl and check all connected clients."""
        acheck(AclBase, new_acl=new_acl)
        self.__ip_acl = new_acl

        for client in self._th_clients:                                     # type: CmdConnection
            ip = client.address
            acl_level = self.__ip_acl.get_level(ip)
            if not acl_level:
                # Disconnect client
                log.warning("client {0} removed from acl - disconnect!".format(ip))
                client.stop()

            elif acl_level != client._acl:
                # Patch acl level in client thread
                log.warning(
                    "change acl level from {0} to {1} on existing "
                    "connection {2}".format(acl_level, client._acl, ip)
                )
                client._acl = acl_level

    def register(self, function: type, name=""):
        self.__register_function(RegisterType.USER, function, name)

    def register_connect(self, function: type):
        self.__register_function(RegisterType.CONNECT, function)

    def register_disconnect(self, function: type):
        self.__register_function(RegisterType.DISCONNECT, function)

    def run(self):
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

        self._exitcode = 0

        log.debug("leave CmdServer.run()")

    def stop(self):
        """Close all connections and sockets."""
        log.debug("enter CmdServer.stop()")

        self._evt_exit.set()
        if self._so is not None:
            try:
                self._so.shutdown(socket.SHUT_RDWR)
            except Exception as e:
                log.exception(e)

        log.debug("leave CmdServer.stop()")

    @property
    def exitcode(self):
        """Get exitcode."""
        return self._exitcode


class CmdConnection(Thread):

    """Handle connection to client and do the jobs."""

    def __init__(self, client_socket: socket.socket, acl_level: int, cmd_handler: type, timeout=5.0):
        """Init CmdHandler class.

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
        self.__evt_exit = Event()
        self.__timeout = timeout

        self.__addr, self.__port = client_socket.getpeername()

        # Set first timeout till config cmd
        self.__con.settimeout(self.__timeout)

    def __handle_exception(self, ex: Exception):
        log.exception(ex)

        # Send exception to client
        b_ex = dumps(ex)
        self.__con.sendall(struct.pack(
            "<s2sI8ss", b'\x01',
            b'\x06E',
            len(b_ex),
            b'\x00' * 8, b'\x17'
        ) + b_ex)

    def __handle_response(self, status: bool, payload=b''):
        do_log = len(payload) > 0
        if do_log:
            log.debug(
                "enter __handle_response status={0} len(payload)={1}"
                "".format(status, len(payload))
            )

        self.__con.sendall(struct.pack(
            "<s2sI8ss", b'\x01',
            b'\x06O' if status else b'\x06E',
            len(payload),
            b'\x00' * 8, b'\x17'
        ) + payload)

        if do_log:
            log.debug(
                "leave __handle_response status={0} len(payload)={1}"
                "".format(status, len(payload))
            )

    def run(self):
        """Execute the requests of client."""
        log.debug("enter CmdHandler.run()")
        log.info("got new connection from host {0} with acl {1}".format(self.__addr, self.__acl))

        # Starting connection handling
        try:
            # Call user function for connect event
            client = CmdClient(self.__addr, self.__port, self.__acl, self.__connected_since)
            if not self.__cmd.connect(client):
                log.warning("connect function does not return True - disconnect")
                self.__evt_exit.set()
        except Exception as e:
            log.exception(e)
            self.__evt_exit.set()

        dirty = True
        while not self.__evt_exit.is_set():
            # Start calculating runtime
            ot = time()

            # Receive full command or disconnect
            try:
                # bCM000000000000b = 16
                net_cmd = self.__con.recv(16)
                if not net_cmd:
                    break
                p_start, cmd, payload, p_end = struct.unpack("<s2s12ss", net_cmd)
            except Exception as e:
                log.exception(e)
                break

            # Check received net command or disconnect
            if not (p_start == b'\x01' and p_end == b'\x17'):
                log.error("net cmd not valid {0}".format(net_cmd))
                break

            if cmd == b'\x06\x16':
                # Synchronous idle
                self.__handle_response(True)

            elif cmd == b'\x06C':
                # Configure socket on client demand
                # bCMii0000000000b = 16

                try:
                    timeout_ms, blob = struct.unpack("<H10s", payload)
                except Exception as e:
                    self.__handle_exception(e)
                    break

                self.__timeout = timeout_ms / 1000
                self.__con.settimeout(self.__timeout)
                log.debug("set socket timeout to {0}".format(self.__timeout))

                self.__handle_response(True)
                continue

            elif cmd == b'\x06F':
                # Call a function of CmdHandler
                # bCMcaaaakkkk000b = 16
                try:
                    len_command, len_args, len_kwargs, blob = struct.unpack("<BII3s", payload)
                except Exception as e:
                    self.__handle_exception(e)
                    continue

                # Command parsed successfully
                self.__handle_response(True)

                # Process payload
                try:
                    b_command = recv_data(self.__con, len_command, self.__evt_exit)
                    b_args = recv_data(self.__con, len_args, self.__evt_exit)
                    b_kwargs = recv_data(self.__con, len_kwargs, self.__evt_exit)

                    command = b_command.decode("ASCII")
                    args = () if len_args == 0 else loads(b_args)
                    kwargs = {} if len_kwargs == 0 else loads(b_kwargs)

                    # Search and call user function of Handler
                    if command in ["connect", "disconnect"]:
                        raise AttributeError(
                            "'{0}' object has no attribute '{1}'"
                            "".format(self.__cmd.__class__.__name__, command)
                        )
                    func = getattr(self.__cmd, command)
                    rc = func(
                        CmdClient(self.__addr, self.__port, self.__acl, self.__connected_since),
                        *args, **kwargs
                    )

                except Exception as e:
                    self.__handle_exception(e)
                else:
                    if rc is None:
                        self.__handle_response(True)
                    else:
                        b_rc = dumps(rc)
                        self.__handle_response(True, b_rc)

            elif cmd == b'\x06L':
                # Get function list of handler
                lst = []
                for func in self.__cmd.__class__.__dict__:
                    if func.find("_") != 0:
                        lst.append(func)
                self.__handle_response(True, dumps(lst))

            elif cmd == b'\x06\x04':
                # End of transmission
                dirty = False
                self.__evt_exit.set()
                continue

            else:
                # No supported command - disconnect
                log.error("found unknown net cmd: {0}".format(cmd))
                break

            # Calculate process time
            # FIXME: Wird bei Zeitänderung immer aufgerufen
            com_time = time() - ot
            if com_time > self.__timeout:
                log.warning("runtime more than {0} ms: {1}!".format(
                    int(self.__timeout * 1000), int(com_time * 1000)
                ))
                # TODO: Should this end up to an exception?

        # Call clean up function
        try:
            self.__cmd.disconnect(
                CmdClient(self.__addr, self.__port, self.__acl, self.__connected_since), dirty
            )
            if dirty:
                log.error("dirty shutdown of connection")
        except Exception as e:
            log.exception(e)

        self.__connected = False
        self.__con.close()

        log.info("disconnected from {0}".format(self.__addr))
        log.debug("leave RevPiSlaveDev.run()")

    def stop(self):
        """Quit command executing of mainloop and exit."""
        log.debug("enter CmdHandler.stop()")

        self.__evt_exit.set()
        if self.__connected:
            self.__con.shutdown(socket.SHUT_RDWR)

        log.debug("leave CmdHandler.stop()")

    @property
    def address(self):
        return self.__addr

    @property
    def connected(self):
        return self.__connected

    @property
    def port(self):
        return self.__port
