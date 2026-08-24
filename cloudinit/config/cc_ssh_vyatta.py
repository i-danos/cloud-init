import logging
# vi: ts=4 expandtab
#
#    Copyright (C) 2019 AT&T Intellectual Property.  All rights reserved.
#    Copyright (C) 2015 Brocade Communication Systems, Inc.
#    Copyright (C) 2009-2010 Canonical Ltd.
#    Copyright (C) 2012, 2013 Hewlett-Packard Development Company, L.P.
#
#    Author: Scott Moser <scott.moser@canonical.com>
#    Author: Juerg Haefliger <juerg.haefliger@hp.com>
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

import glob
import os

# Ensure this is aliased to a name not 'distros'
# since the module attribute 'distros'
# is a list of distros that are supported, not a sub-module
from cloudinit.distros import ug_util

from cloudinit import ssh_util
from cloudinit import subp
from cloudinit import util
from cloudinit.log import log_util
from cloudinit.cloud import Cloud
from cloudinit.config import Config
from cloudinit.config.schema import MetaSchema
from cloudinit.distros import ALL_DISTROS
from cloudinit.settings import PER_INSTANCE

LOG = logging.getLogger(__name__)

meta: MetaSchema = {
    "id": "cc_ssh_vyatta",
    "distros": ["vrouter"],
    "frequency": PER_INSTANCE,
    "activate_by_schema_keys": [],
}

import os
from vyatta import configd

DISABLE_ROOT_OPTS = ("disable-tcp-forwarding")

KEY_2_FILE = {
    "rsa_private": ("/etc/ssh/ssh_host_rsa_key", 0o600),
    "rsa_public": ("/etc/ssh/ssh_host_rsa_key.pub", 0o644),
    "dsa_private": ("/etc/ssh/ssh_host_dsa_key", 0o600),
    "dsa_public": ("/etc/ssh/ssh_host_dsa_key.pub", 0o644),
    "ecdsa_private": ("/etc/ssh/ssh_host_ecdsa_key", 0o600),
    "ecdsa_public": ("/etc/ssh/ssh_host_ecdsa_key.pub", 0o644),
}

def handle(name: str, cfg: Config, cloud: Cloud, args: list) -> None:

    # remove the static keys from the pristine image
    if cfg.get("ssh_deletekeys", True):
        key_pth = os.path.join("/etc/ssh/", "ssh_host_*key*")
        for f in glob.glob(key_pth):
            try:
                util.del_file(f)
            except:
                log_util.logexc(LOG, "Failed deleting key file %s", f)

    if "ssh_keys" in cfg:
        # if there are keys in cloud-config, use them
        for (key, val) in cfg["ssh_keys"].items():
            if key in KEY_2_FILE:
                tgt_fn = KEY_2_FILE[key][0]
                tgt_perms = KEY_2_FILE[key][1]
                util.write_file(tgt_fn, val, tgt_perms)

    else:
        # if not, generate them
        cmd = ['sh', '-c', 'echo "configure\n/opt/vyatta/sbin/vyatta-update-ssh.pl > /etc/ssh/sshd_config" | vcli' ]
        try:
            # TODO(harlowja): Is this guard needed?
            with util.SeLinuxGuard("/etc/ssh", recursive=True):
                subp.subp(cmd, capture=False)
            LOG.debug("Generated new SSH keys");
            # restart sshd?
        except:
            log_util.logexc(LOG, "Failed to generate SSH keys");

    # Restart SSH after creating/placing host keys
    cmd = ['systemctl', 'restart', 'ssh.service']
    subp.subp(cmd, capture=False)

    try:
        (users, _groups) = ug_util.normalize_users_groups(cfg, cloud.distro)
        (user, _user_config) = ug_util.extract_default(users)
        disable_root = util.get_cfg_option_bool(cfg, "disable_root", True)
        disable_root_opts = util.get_cfg_option_str(cfg, "disable_root_opts",
                                                    DISABLE_ROOT_OPTS)

        keys = cloud.get_public_ssh_keys() or []
        if "ssh_authorized_keys" in cfg:
            cfgkeys = cfg["ssh_authorized_keys"]
            keys.extend(cfgkeys)

        apply_credentials(keys, user, disable_root, disable_root_opts)
    except:
        log_util.logexc(LOG, "Applying ssh credentials failed!")


def apply_credentials(keys, user, disable_root, disable_root_opts):
    client = configd.Client()
    sessid = str(os.getpid())
    result = client.session_setup(sessid)

    if user:
        keyNo = 0
        for key in keys:
            key = key.encode('ascii', 'ignore')
            split_key = key.split()
            keyType = split_key[0]
            keyBase64 = split_key[1]

            path = [ "system", "login", "user", user,
                     "authentication", "public-keys", str(keyNo) ]
            if client.node_exists(client.AUTO, path):
                result = client.delete(path)
                result = client.commit("")
            path = [ "system", "login", "user", user,
                     "authentication", "public-keys", str(keyNo),
                     "key", keyBase64.decode('ascii') ]
            result = client.set(path)
            path = [ "system", "login", "user", user,
                     "authentication", "public-keys", str(keyNo),
                     "type", keyType.decode('ascii') ]
            result = client.set(path)
            keyNo = keyNo + 1
        result = client.commit("")

    if disable_root:
            path = [ "service", "ssh", "allow-root" ]
            if client.node_exists(client.AUTO, path):
                result = client.delete(path)
                result = client.commit("")

    if disable_root_opts:
        changed = False
        opts = disable_root_opts.split(',')
        for opt in opts:
            path = [ "service", "ssh", opt ]
            if not client.node_exists(client.AUTO, path):
                result = client.set(path)
                changed = True
        if changed:
            result = client.commit("")
