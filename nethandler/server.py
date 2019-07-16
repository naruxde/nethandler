# -*- coding: utf-8 -*-
"""Server for network file handler."""
__author__ = "Sven Sager"
__copyright__ = "Copyright (C) 2019 Sven Sager"
__license__ = "GPLv3"
import socket
from logging import getLogger
from pickle import dumps, loads
from threading import Event, Thread
from timeit import default_timer

from .acl import AclBase
from .helper import acheck

log = getLogger()


class CmdHandler:

    def connect(self, client_ip: str, client_port: int, client_acl: int):
        return True

    def disconnect_clean(self, client_ip: str, client_port: int):
        pass

    def disconnect_dirty(self, client_ip: str, client_port: int):
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

    def change_ip_acl(self, new_ip_acl: AclBase):
        """Change ip acl and check all connected clients."""
        acheck(AclBase, new_ip_acl=new_ip_acl)
        self.__ip_acl = new_ip_acl

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
        self.__evt_exit = Event()
        self.__timeout = timeout

        self.__addr, self.__port = client_socket.getpeername()

        # Set first timeout till config cmd
        self.__con.settimeout(self.__timeout)

    def __handle_exception(self, ex: Exception):
        log.exception(ex)

        # Send exception to client
        b_ex = dumps(ex)
        self.__con.send(
            b'\x01\x06E' +
            len(b_ex).to_bytes(4, byteorder="little") +
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x17' +
            b_ex
        )

    def __handle_data(self, length: int):
        data = bytearray()
        position = 0
        while not (position == length or self.__evt_exit.is_set()):
            block = length - position
            buff = self.__con.recv(block)
            if buff == b'':
                break
            position += len(buff)
            data += buff

        return bytes(data)

    def __handle_response(self, status: bool, payload=b''):
        b_status = b'\x06O' if status else b'\x06E'
        self.__con.sendall(
            b'\x01' + b_status +
            len(payload).to_bytes(4, byteorder="little") +
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x17' +
            payload
        )

    def run(self):
        """Execute the requests of client."""
        log.debug("enter CmdHandler.run()")
        log.info("got new connection from host {0} with acl {1}".format(self.__addr, self.__acl))

        # Starting connection handling
        try:
            # Call user function for connect event
            if not self.__cmd.connect(self.__addr, self.__port, self.__acl):
                log.warning("connect function does not return True - disconnect")
                self.__evt_exit.set()
        except Exception as e:
            log.exception(e)
            self.__evt_exit.set()

        dirty = True
        while not self.__evt_exit.is_set():
            # Start calculating runtime
            ot = default_timer()

            # Receive full command or disconnect
            try:
                net_cmd = self.__con.recv(16)
            except Exception as e:
                log.exception(e)
                break

            # Check received net command or disconnect
            if net_cmd[0:1] != b'\x01' or net_cmd[-1:] != b'\x17':
                if net_cmd != b'':
                    log.error("net cmd not valid {0}".format(net_cmd))
                break

            # bCM000000000000b = 16
            cmd = net_cmd[1:3]

            if cmd == b'\x06\x16':
                # Synchronous idle
                self.__handle_response(True)

            elif cmd == b'\x06C':
                # Configure socket on client demand
                # bCMii0000000000b = 16

                try:
                    timeout_ms = int.from_bytes(net_cmd[3:5], byteorder="little")
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
                # bCMiiiiiiiiiiiib = 16
                try:
                    len_command = int.from_bytes(net_cmd[3:7], byteorder="little")
                    len_args = int.from_bytes(net_cmd[7:11], byteorder="little")
                    len_kwargs = int.from_bytes(net_cmd[11:15], byteorder="little")
                except Exception as e:
                    self.__handle_exception(e)
                    continue

                # Command parsed successfully
                self.__handle_response(True)

                # Process payload
                try:
                    command = self.__con.recv(len_command).decode("ASCII")
                    args = () if len_args == 0 else loads(self.__handle_data(len_args))
                    kwargs = {} if len_kwargs == 0 else loads(self.__handle_data(len_kwargs))
                except Exception as e:
                    self.__handle_exception(e)
                    continue

                # Search and call user function of Handler
                try:
                    func = getattr(self.__cmd, command)
                    rc = func(self.__acl, *args, **kwargs)
                except Exception as e:
                    self.__handle_exception(e)
                    continue

                if rc is None:
                    self.__handle_response(True)
                else:
                    b_rc = dumps(rc)
                    self.__handle_response(True, b_rc)

            elif cmd == b'\x06L':
                # Get function list of handler
                lst = []
                for func in dir(self.__cmd):
                    if func.find("_") == -1:
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
            com_time = default_timer() - ot
            if com_time > self.__timeout:
                log.warning("runtime more than {0} ms: {1}!".format(
                    int(self.__timeout * 1000), int(com_time * 1000)
                ))
                # TODO: Should this end up to an exception?

        # Call clean up function
        try:
            if dirty:
                log.error("dirty shutdown of connection")
                self.__cmd.disconnect_dirty(self.__addr, self.__port)
            else:
                self.__cmd.disconnect_clean(self.__addr, self.__port)
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
