# -*- coding: utf-8 -*-
"""Net handler for communication between server and clients."""
from .client import CmdClient
from .server import CmdServer, CmdHandler
__all__ = [
    "CmdClient",
    "CmdServer", "CmdHandler"
]
__author__ = "Sven Sager"
__copyright__ = "Copyright (C) 2019 Sven Sager"
__license__ = "GPLv3"
__name__ = "nethandler"
__version__ = "0.0.1"
