# -*- coding: utf-8 -*-
"""Helper functions and classes for network file handler."""
__author__ = "Sven Sager"
__copyright__ = "Copyright (C) 2019 Sven Sager"
__license__ = "GPLv3"


def acheck(check_type, **kwargs):
    """Check type of given arguments.

    Use the argument name as keyword and the argument itself as value.

    @param check_type Type to check
    @param kwargs Arguments to check

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
