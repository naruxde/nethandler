# -*- coding: utf-8 -*-
"""Helper functions and classes for network file handler."""
__author__ = "Sven Sager"
__copyright__ = "Copyright (C) 2019 Sven Sager"
__license__ = "GPLv3"
from logging import getLogger
from socket import socket
from threading import Event
from time import time
log = getLogger()


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


def recv_data(connection: socket, length: int, cancel_event=Event()) -> bytes:
    """Receive defined amount of data from socket.

    :param connection: Socket connection to receive data from
    :param length: Length to receive
    :param cancel_event: Cancel receiving data if event is set
    :return: Received bytes or None
    """

    # Shortcut for zero length
    if length == 0:
        return b''

    log.debug("enter helper.recv_data length={0}".format(length))

    data = bytearray()
    null_byte_count = 0
    null_byte_max = int(length / 10)
    position = 0
    while not (position == length or cancel_event.is_set()):
        buff = connection.recv(length - position)
        if buff == b'':
            null_byte_count += 1
            if null_byte_count == null_byte_max:
                break
        position += len(buff)
        data += buff

    log.debug("leave helper.recv_data got {0} bytes of {1} requested".format(position, length))

    if length == position:
        return bytes(data)

    if cancel_event.is_set():
        raise RuntimeError("receive data aborted with cancel event")

    raise RuntimeError("received {0} bytes of requested {1}".format(position, length))
