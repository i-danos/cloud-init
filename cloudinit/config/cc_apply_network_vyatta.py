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

from cloudinit.settings import PER_INSTANCE
from cloudinit.cloud import Cloud
from cloudinit.config import Config
from cloudinit.config.schema import MetaSchema

meta: MetaSchema = {
    "id": "cc_apply_network_vyatta",
    "distros": ["vrouter"],
    "frequency": PER_INSTANCE,
    "activate_by_schema_keys": [],
}
import logging
from cloudinit import subp
from cloudinit import util

frequency = PER_INSTANCE
LOG = logging.getLogger(__name__)

import os
from vyatta import configd

def _calc_subnetlen(cidr):
    # convert to binary string and count the 1's
    return sum([bin(int(octect)).count('1') for octect in cidr.split('.')])

def parse_network_interfaces(contents):
    network_interfaces = {}
    current_interface = None
    network_interfaces_file = contents.splitlines()
    for line in network_interfaces_file:
        tokens = line.split()
        if tokens[0] == 'iface':
            network_interfaces[tokens[1]] = {}
            current_interface = network_interfaces[tokens[1]]
            current_interface['iface'] = tokens[1]
            if tokens[3] == 'dhcp':
                current_interface['dhcp'] = True
        if tokens[0] == 'address':
            #if current_interface:
                current_interface['address'] = tokens[1]
        if tokens[0] == 'netmask':
            if current_interface:
                current_interface['netmask'] = tokens[1]
        if tokens[0] == 'broadcast':
            if current_interface:
                current_interface['broadcast'] = tokens[1]
        if tokens[0] == 'gateway':
            if current_interface:
                current_interface['gateway'] = tokens[1]
    return network_interfaces

def handle(name: str, cfg: Config, cloud: Cloud, _args: list) -> None:
    metadata = cloud.datasource.metadata
    if not metadata or not 'network-interfaces' in metadata:
        return

    client = configd.Client()
    sessid = str(os.getpid())
    result = client.session_setup(sessid)
    network_interfaces = parse_network_interfaces(metadata['network-interfaces'])

    for interface in network_interfaces:
        interface = network_interfaces[interface]

        intf = [ 'interfaces', 'dataplane', interface['iface'] ]
        if client.node_exists(client.AUTO, intf):
            result = client.delete(intf)
        if interface.get('dhcp'):
            result = client.set(intf + ['address', 'dhcp'])
        if interface.get('address'):
            len = _calc_subnetlen(interface['netmask'])
            result = client.set(intf + ['address', interface['address'] + '/' + str(len)])
        if interface.get('gateway'):
            path = ['protocols', 'static', 'route', '0.0.0.0/32', 'next-hop']
            if client.node_exists(client.AUTO, path):
                result = client.delete(path)
            result = client.set(path + [interface['gateway']])
        result = client.commit("")
    return
