# -*- coding: utf-8 -*-
"""Helper functions and classes for network file handler."""
__author__ = "Sven Sager"
__copyright__ = "Copyright (C) 2019 Sven Sager"
__license__ = "GPLv3"

from logging import getLogger
from socket import AF_INET, SOCK_STREAM, getdefaulttimeout, socket
from threading import Event

log = getLogger()

HEADER_START = b'\x01'  # First Byte of net cmd
HEADER_STOP = b'\x17'  # Last Byte of net cmd


def acheck(check_type, **kwargs) -> None:
    """
    Check type of given arguments.

    Use the argument name as keyword and the argument itself as value.

    :param check_type: Type to check
    :param kwargs: Arguments to check
    """
    for var_name in kwargs:
        none_okay = var_name.endswith("_noneok")

        if not (isinstance(kwargs[var_name], check_type) or none_okay and kwargs[var_name] is None):
            msg = "Argument '{0}' must be {1}{2}".format(
                var_name.rstrip("_noneok"),
                str(check_type),
                " or <class 'NoneType'>" if none_okay else ""
            )
            raise TypeError(msg)


class HandlerSocket(socket):
    """Special socket with save receive all method."""

    def __init__(self, family=AF_INET, type=SOCK_STREAM, proto=0, fileno=None):
        self.__buff_size = 2048
        self.__buff_block = bytearray(self.__buff_size)
        self.__buf_data = bytearray()
        super(HandlerSocket, self).__init__(family=family, type=type, proto=proto, fileno=fileno)

    def accept(self):
        """accept() -> (socket object, address info)

        Wait for an incoming connection.  Return a new socket
        representing the connection, and the address of the client.
        For IP sockets, the address info is a pair (hostaddr, port).
        """
        fd, addr = self._accept()
        # If our type has the SOCK_NONBLOCK flag, we shouldn't pass it onto the
        # new socket. We do not currently allow passing SOCK_NONBLOCK to
        # accept4, so the returned socket is always blocking.
        type = self.type & ~globals().get("SOCK_NONBLOCK", 0)
        sock = HandlerSocket(self.family, type, self.proto, fileno=fd)
        # Issue #7995: if no default timeout is set and the listening
        # socket had a (non-zero) timeout, force the new socket in blocking
        # mode to override platform-specific socket flags inheritance.
        if getdefaulttimeout() is None and self.gettimeout():
            sock.setblocking(True)
        return sock, addr

    def recvall(self, length: int, cancel_event=Event()) -> bytes:
        """Receive defined amount of data from socket.

        :param length: Length to receive
        :param cancel_event: Cancel receiving data if event is set
        :return: Received bytes or None
        """

        # Shortcut for zero length
        if length == 0:
            return b''

        self.__buf_data.clear()
        while length > 0 and not cancel_event.is_set():
            count = self.recv_into(self.__buff_block, min(length, self.__buff_size))
            if count == 0:
                break
            length -= count
            self.__buf_data += self.__buff_block[:count]

        if length == 0:
            return bytes(self.__buf_data)

        if cancel_event.is_set():
            raise RuntimeError("receive data aborted with cancel event")

        raise RuntimeError("received {0} bytes and miss {1} bytes".format(len(self.__buf_data), length))
