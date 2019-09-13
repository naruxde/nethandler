# -*- coding: utf-8 -*-
"""Access control list for network handler."""
__author__ = "Sven Sager"
__copyright__ = "Copyright (C) 2019 Sven Sager"
__license__ = "GPLv3"
from ipaddress import AddressValueError, IPv4Address, IPv4Network, IPv6Address, IPv6Network
from re import compile as recompile
from warnings import warn

from .helper import acheck


class AclBase:
    """Base class for all ACL special classes."""

    __slots__ = "__dict_known_ips", "__buffer_acl"

    def __init__(self, buffer_acl=True):
        """Base class with main function of the acl system.

        :param buffer_acl: Buffer levels of ip to speed up checks
        """
        acheck(bool, buffer_acl=buffer_acl)

        self.__buffer_acl = buffer_acl
        self.__dict_known_ips = {}

    def check_level_ipv4(self, ip_address: IPv4Address) -> int:
        """Override with function to check the level of given IPv4.

        :param ip_address: Ip address to check
        :return: Level of ip address or None
        """
        return

    def check_level_ipv6(self, ip_address: IPv6Address) -> int:
        """Override with function to check the level of given IPv6.

        :param ip_address: Ip address to check
        :return: Level of ip address or None
        """
        return

    def clear_buffer(self) -> None:
        """Clears the alc buffer of saved ip levels."""
        self.__dict_known_ips.clear()

    def get_level(self, ip_address: str) -> int:
        """Get the access control level for given ip address v4 / v6.

        This function will detect the kind of IP version and checks it
        against given ACLs. If the buffer parameter was True on init, the
        acl will be delivered from buffer.

        :param ip_address: Ip address to check
        :return: Level of ip address or None
        """
        if ip_address in self.__dict_known_ips:
            return self.__dict_known_ips[ip_address]

        # Pre check ip address
        acheck(str, ip_address=ip_address)
        if ip_address.find("/") >= 0:
            warn(
                "Ip address must be without subnet",
                RuntimeWarning
            )
        else:
            try:
                if ip_address.find(".") == -1:
                    # Should be IPv6
                    check_ip = IPv6Address(ip_address)
                    level = self.check_level_ipv6(check_ip)
                else:
                    # Should be IPv4
                    check_ip = IPv4Address(ip_address)
                    level = self.check_level_ipv4(check_ip)
            except AddressValueError:
                warn(
                    "Can not detect ip address in '{0}'".format(ip_address),
                    RuntimeWarning
                )
            except Exception as e:
                warn(
                    str(e),
                    RuntimeWarning
                )
            else:
                # Save level to known ips and return level
                if self.__buffer_acl:
                    self.__dict_known_ips[ip_address] = level
                return level

    @property
    def buffer(self) -> dict:
        """Get the acl buffer."""
        return self.__dict_known_ips.copy()

    @property
    def buffer_length(self) -> int:
        """Get the alc buffer length."""
        return len(self.__dict_known_ips)


class AclIp(AclBase):
    """
    Manage access control levels by host ip or subnet.

    Define a min and max acl level and assign the levels to single hosts or a
    subnet. You can dump the acl to a file and reload them.
    """

    __slots__ = "__dict_acl", "__min_level", "__max_level"

    def __init__(self, min_level=0, max_level=0, acl_file="", buffer_acl=True) -> None:
        """
        Acl class to set different access levels to ip addresses.

        :param min_level: Minimum level of allowed access level
        :param max_level: Maximum level of allowed access level
        :param acl_file: Filename to load ACLs from
        :param buffer_acl: Buffer levels of ip to speed up checks
        """
        acheck(
            int,
            min_level=min_level, max_value=max_level,
        )
        if min_level > max_level:
            raise ValueError("min_level is greater than than max_level")
        super(AclIp, self).__init__(buffer_acl)

        # Class variables
        self.__dict_acl = {}
        self.__min_level = min_level
        self.__max_level = max_level

        if acl_file:
            self.load_file(acl_file)

    def __contains__(self, item: str) -> bool:
        """
        Check whether ip is in acl independent on level.

        :return: True if ip address is in acl
        """
        return self.get_level(item) is not None

    def __eq__(self, other) -> bool:
        """
        Check whether objects of AclIp are equal.

        :param other: Object to compare
        :return: True if the values are the same
        """
        try:
            return (
                self.__dict_acl == other._AclIp__dict_acl and
                self.__min_level == other.min_level and
                self.__max_level == other.max_level
            )
        except AttributeError:
            return NotImplemented

    def add_acl(self, host_or_net_ip: str, acl_level: int) -> None:
        """
        Add an ip address and the access level.

        The buffer will be cleared if this function is called.

        :param host_or_net_ip: IP address to add
        :param acl_level: Access level of ip address
        """
        acheck(int, acl_level=acl_level)
        acheck(str, host_or_net_ip=host_or_net_ip)

        if not self.__min_level <= acl_level <= self.__max_level:
            raise ValueError(
                "acl_level must be between min ({0}) and max ({1})"
                "".format(self.__min_level, self.__max_level)
            )

        try:
            if host_or_net_ip.find(".") == -1:
                # Should be IPv6
                add_net = IPv6Network(host_or_net_ip)
            else:
                # Should be IPv4
                add_net = IPv4Network(host_or_net_ip)
        except AddressValueError:
            raise ValueError(
                "Can not detect address in '{0}'".format(host_or_net_ip)
            )

        # Check Overlap
        for net in self.__dict_acl:  # type: IPv4Network
            if net.overlaps(add_net):
                raise RuntimeError("The entry '{0}' overlaps '{1}'".format(add_net, net))

        self.__dict_acl[add_net] = acl_level
        self.clear_buffer()

    def check_level_ipv4(self, ip_address: IPv4Address) -> int:
        """Check function which is called from get_level of base class."""
        for net in self.__dict_acl:  # type: IPv4Network
            if ip_address in net:
                return self.__dict_acl[net]

    def check_level_ipv6(self, ip_address: IPv6Address) -> int:
        """Check function which is called from get_level of base class."""
        for net in self.__dict_acl:  # type: IPv6Network
            if ip_address in net:
                return self.__dict_acl[net]

    def clear_acl(self) -> None:
        """Remove all ACLs."""
        self.clear_buffer()
        self.__dict_acl.clear()

    def dumps(self) -> str:
        """Get config file text of all ACLs of this instance."""
        dump_string = ""
        for net in self.__dict_acl:  # type: IPv4Network
            dump_string += "{0},{1}\n".format(net, self.__dict_acl[net])
        return dump_string

    def load_file(self, file_name: str) -> None:
        """
        Load ACL definition from file.

        :param file_name: Filename of acl file
        """
        acheck(str, file_name=file_name)
        line_check = recompile(r"^\s*(?!#)(?P<ip>[0-9a-fA-F:.]+(|(/\d{1,3})?)),(?P<acl>\d+)")

        with open(file_name, "r") as fh:
            while True:
                buff = fh.readline()
                if not buff:
                    break

                ma = line_check.match(buff)
                if not ma:
                    continue

                # Write one acl
                self.add_acl(ma.group("ip"), int(ma.group("acl")))

    def save_file(self, file_name: str) -> None:
        """
        Save ACL definition to a file.

        :param file_name: Filename to save acl data
        """
        acheck(str, file_name=file_name)

        with open(file_name, "w") as fh:
            fh.writelines([
                "# Nethandler ACL file for IPv4 and IPv6 addresses (CIDR)",
                "# Format: IP/PREFIX,LEVEL (127.0.0.1/8,0)"
            ])
            for net in self.__dict_acl:
                fh.write("{0},{1}\n".format(net, self.__dict_acl[net]))

    @property
    def min_level(self) -> int:
        """Get minimum level."""
        return self.__min_level

    @property
    def max_level(self) -> int:
        """Get maximum level."""
        return self.__max_level


class AclIpGroup(AclBase):
    """Manage access control levels by type of ip.

    You can use this class to simply define levels to groups of ip addresses
    depending on their origin. It supports "loopback", "private", "global"
    origins.
    """

    __slots__ = "__dict_known_ips", "__level_global", "__level_loopback", "__level_private"

    def __init__(self, set_loopback_level=0, set_private_level=0, set_global_level=0, buffer_acl=True) -> None:
        """
        Acl class to set different access levels to ip groups.

        :param set_loopback_level: Level of IPs from localhost
        :param set_private_level: Level of IPs from private range
        :param set_global_level: Level of IPs from global range
        :param buffer_acl: Buffer levels of ip to speed up checks
        """
        acheck(
            int,
            set_loopback_level=set_loopback_level,
            set_private_level=set_private_level,
            set_global_level=set_global_level,
        )
        super(AclIpGroup, self).__init__(buffer_acl)

        # Class variables
        self.__level_global = set_global_level
        self.__level_loopback = set_loopback_level
        self.__level_private = set_private_level

    def __eq__(self, other) -> bool:
        """
        Check whether objects of AclIp are equal.

        :param other: Object to compare
        :return: True if the values are the same
        """
        try:
            return (
                self.__level_global == other._AclIpGroup__level_global and
                self.__level_loopback == other._AclIpGroup__level_loopback and
                self.__level_private == other._AclIpGroup__level_private
            )
        except AttributeError:
            return NotImplemented

    def check_level_ipv4(self, ip_address: IPv4Address) -> int:
        """Check function which is called from get_level of base class."""
        if ip_address.is_global:
            return self.__level_global
        elif ip_address.is_loopback:
            return self.__level_loopback
        elif ip_address.is_private:
            return self.__level_private

    def check_level_ipv6(self, ip_address: IPv6Address) -> int:
        """Check function which is called from get_level of base class."""
        if ip_address.is_global:
            return self.__level_global
        elif ip_address.is_loopback:
            return self.__level_loopback
        elif ip_address.is_private:
            return self.__level_private
