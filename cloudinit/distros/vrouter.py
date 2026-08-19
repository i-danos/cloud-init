# vi: ts=4 expandtab
#
#    Copyright (C) 2019 AT&T Intellectual Property.  All rights reserved.
#    Copyright (C) 2015 Brocade Communication Systems, Inc.
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License version 3, as
#    published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

from cloudinit import distros
from cloudinit import helpers
import logging
from cloudinit import subp
from cloudinit import util

from cloudinit.distros.parsers.hostname import HostnameConf
from cloudinit.settings import PER_INSTANCE

LOG = logging.getLogger(__name__)

import os
from vyatta import configd
from pwd import getpwnam

class Distro(distros.Distro):
    locale_conf_fn = "/etc/default/locale"
    systemd_locale_conf_fn = '/etc/locale.conf'
    network_conf_fn = "/etc/network/interfaces"
    tz_local_fn = "/etc/localtime"
    client = None

    def __init__(self, name, cfg, paths):
        distros.Distro.__init__(self, name, cfg, paths)
        # This will be used to restrict certain
        # calls from repeatly happening (when they
        # should only happen say once per instance...)
        self._runner = helpers.Runners(paths)
        self.osfamily = 'vrouter'

    def __lu(self):
        """Change loginuid so that configd permits configuration changes."""
        uid = getpwnam('configd').pw_uid
        lu = open('/proc/self/loginuid', 'w')
        lu.truncate()
        lu.write(str(uid))
        lu.close()

    def SetupSession(self):
        if not self.client:
            self.__lu()
            self.client = configd.Client()
            sessid = str(os.getpid())
            result = self.client.session_setup(sessid)

    #
    # configd is not running at this point so we can't apply a network
    # configuration.  The metadata is already stored in the cache which
    # will be read by a module during the config stage.
    #

    def apply_network_config(self, netconfig, bring_up=False):
        return

    def apply_network_config_names(self, netconfig):
        return

    #
    # The following functions are called during 'init phase' which is executed
    # before the configd system loaded the initial configuration file.
    #

    def _read_hostname(self, filename, default=None):
        pass

    def _read_system_hostname(self):
        pass

    def _write_hostname(self, your_hostname, out_fn):
        pass

    def _select_hostname(self, hostname, fqdn):
        # Prefer the short hostname over the long
        # fully qualified domain name
        if not hostname:
            return fqdn
        return hostname

    def set_hostname(self, hostname, fqdn=None):
        hostname = self._select_hostname(hostname, fqdn)
        self.SetupSession()
        path = [ "system", "host-name" ]

        if self.client.node_exists(self.client.AUTO, path + [ hostname ]):
            return

        if self.client.node_exists(self.client.AUTO, path) and not self.client.node_is_default(self.client.AUTO, path):
            result = self.client.delete(path)
        result = self.client.set(path + [ hostname ])
        result = self.client.commit("")

    def update_hostname(self, hostname, fqdn, prev_hostname_fn):
        self.set_hostname(hostname, fqdn)

    def create_user(self, name, **kwargs):
        self.add_user(name, **kwargs)

        # Default locking down the account. 'lock_passwd' defaults to True.
        # lock account unless lock_password is False.
        if kwargs.get('lock_passwd', True):
            self.lock_passwd(name)

        # Import SSH keys
        if 'ssh_authorized_keys' in kwargs:
            keys = set(kwargs['ssh_authorized_keys']) or []
            self.setup_user_keys(keys, name, options=None)

    def setup_user_keys(self, keys, user, options):
        keyNo = 0
        path = [ "system", "login", "user", user,
                 "authentication", "public-keys" ]
        if self.client.node_exists(self.client.AUTO, path):
            result = self.client.delete(path)

        for key in keys:
            key = key.encode('ascii', 'ignore')
            split_key = key.split()
            keyType = split_key[0]
            keyBase64 = split_key[1]
            result = self.client.set(path + [str(keyNo), "key", keyBase64.decode('ascii')])
            result = self.client.set(path + [str(keyNo), "type", keyType.decode('ascii')])
            keyNo = keyNo + 1
        result = self.client.commit("")

    def add_user(self, user, **kwargs):
        """
        Add a user to the system using Vyatta CLI
        Called in 'config' phase.
        """
        self.SetupSession()

        path = [ "system", "login", "user", user ]
        if not self.client.node_exists(self.client.AUTO, path):
            result = self.client.set(path)

        path = [ "system", "login", "user", user, "full-name" ]
        if self.client.node_exists(self.client.AUTO, path):
            result = self.client.delete(path)
        if 'gecos' in kwargs:
            result = self.client.set(path + [kwargs['gecos']])

        path = [ "system", "login", "user", user, "home-directory" ]
        if self.client.node_exists(self.client.AUTO, path):
            result = self.client.delete(path)
        if 'homedir' in kwargs:
            result = self.client.set(path + [kwargs['homedir']])

        path = [ "system", "login", "user", user, "level" ]
        if self.client.node_exists(self.client.AUTO, path) and not self.client.node_is_default(self.client.AUTO, path):
            result = self.client.delete(path)
        if 'sudo' in kwargs:
            result = self.client.set(path + ["superuser"])

        path = [ "system", "login", "user", user, "authentication",
                 "encrypted-password" ]
        if self.client.node_exists(self.client.AUTO, path):
            result = self.client.delete(path)
        if 'passwd' in kwargs:
            result = self.client.set(path + [kwargs['passwd']])

        result = self.client.commit("")

    def set_passwd(self, user, passwd, hashed=False):
        """Called in 'config' phase"""
        self.SetupSession()
        path = [ "system", "login", "user", user, "authentication" ]
        if hashed:
            path.append([ "encrypted-password" ])
        else:
            path.append([ "plaintext-password" ])
        if self.client.node_exists(self.client.AUTO, path):
            result = self.client.delete(path)
        result = self.client.set(path + [ passwd ])
        result = self.client.commit("")

    def create_group(self, name, members):
        self.SetupSession()
        path = [ "system", "login", "group", name ]
        if not self.client.node_exists(self.client.AUTO, path):
            result = self.client.set(path)
            result = self.client.commit("")

        # members -- TODO

    def lock_passwd(self, user):
        """
        Lock the password of a user, i.e., disable password logins
        Called in 'config' phase.
        """
        self.SetupSession()
        path = [ "system", "login", "user", user, "authentication", "encrypted-password" ]
        if self.client.node_exists(self.client.AUTO, path):
            result = self.client.delete(path)

        result = self.client.set(path + [ "*" ])
        result = self.client.commit("")

    #
    # The following functions are called during 'config phase' which is executed
    # after the configd system loaded the initial configuration file.
    #


    def apply_locale(self, locale, out_fn=None):
        if not out_fn:
            if self._dist_uses_systemd():
                out_fn = self.systemd_locale_conf_fn
            else:
                out_fn = self.locale_conf_fn
        subp.subp(['locale-gen', locale], capture=False)
        subp.subp(['update-locale', locale], capture=False)
        # "" provides trailing newline during join
        lines = [
            util.make_header(),
            'LANG="%s"' % (locale),
            "",
        ]
        util.write_file(out_fn, "\n".join(lines))

    def set_timezone(self, tz):
        tz_file = self._find_tz_file(tz)
        # FIXME: Write TZ to config.boot "set system time-zone"
        if self._dist_uses_systemd():
            # Currently, timedatectl complains if invoked during startup
            # so for compatibility, create the link manually.
            util.del_file(self.tz_local_fn)
            util.sym_link(tz_file, self.tz_local_fn)
        else:
            distros.set_etc_timezone(tz=tz, tz_file=tz_file)

    def install_packages(self, pkglist):
        return

    def package_command(self, command, args=None, pkgs=None):
        return

    def update_package_sources(self):
        return
