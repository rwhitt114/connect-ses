#!/usr/bin/python

############################################################################
#
# AVI CONFIDENTIAL
# __________________
#
# [2013] - [2018] Avi Networks Incorporated
# All Rights Reserved.
#
# NOTICE: All information contained herein is, and remains the property
# of Avi Networks Incorporated and its suppliers, if any. The intellectual
# and technical concepts contained herein are proprietary to Avi Networks
# Incorporated, and its suppliers and are covered by U.S. and Foreign
# Patents, patents in process, and are protected by trade secret or
# copyright law, and other laws. Dissemination of this information or
# reproduction of this material is strictly forbidden unless prior written
# permission is obtained from Avi Networks Incorporated.
###

"""
- Sync current secure channel certificate with SEs
"""
import shlex
import os
import argparse
import traceback
import yaml
import re
import subprocess32 as subprocess
from fabric.api import (env, execute, task, sudo, put, settings)
from avi.util.host_utils import (setup_env_for_se_fab_task, FabricTask)
from avi.infrastructure.clustering.config_utils import SE_LIST_FILE


@task(task_class=FabricTask, command_timeout=10)
def sync_se_entries(username, password, port):
    env.port = port
    with settings(warn_only=True):
        if not username:
            setup_env_for_se_fab_task(env)
        else:
            env.user = username
            env.password = password
        # copy cert files
        put('/var/lib/avi/ca/certs/cacert.pem',
            '/bootstrap/cacert.pem', use_sudo=True)
        put('/var/lib/avi/ca/local/cn.txt',
            '/bootstrap/cn.txt', use_sudo=True)
        # ensure SE uses current Controllers, not something in OVF
        put('/var/lib/avi/etc/zk_servers.txt',
            '/var/lib/avi/etc/zk_servers.txt', use_sudo=True)

        sudo('systemctl stop se_supervisor.service; systemctl start se_supervisor.service')


def find_ses_using_reverse_tunnel():
    se_rev_ip_list = []
    try:
        netstat_cmd = 'netstat -l'
        srch_cmd = 'awk \'/tcp/ && /:5097/ && /LISTEN/\''
        print('ssh find rev tunnels: %s | %s' % (netstat_cmd, srch_cmd))

        netstat_p = subprocess.Popen(shlex.split(netstat_cmd),
                                     stdout=subprocess.PIPE)
        srch_p = subprocess.Popen(shlex.split(srch_cmd),
                                  stdin=netstat_p.stdout,
                                  stdout=subprocess.PIPE)
        netstat_p.stdout.close()
        output, error = srch_p.communicate()
        netstat_p.wait()

        if output and len(output):
            print('out: %s' % output)
            for line in output.splitlines():
                match_obj = re.match(
                    r'\s*tcp\s*\d*\s*\d*\s*([0-9\.]+):5097\s*.*LISTEN\s*', line)
                if match_obj:
                    reverse_ip = match_obj.group(1)
                    if reverse_ip:
                        se_rev_ip_list.extend([reverse_ip])
                    else:
                        print("error, no match: %s" % line)
        elif error and len(error):
            print('err: %s' % error)

    except Exception as ex:
        print('ssh rev ip check ex. [out=%s][err:%s]'
              ',err: %s' % (output, error, ex))
    return se_rev_ip_list


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Sync current secure channel certificate with SEs')
    parser.add_argument('--se', required=False, action='append', default=[])
    parser.add_argument('--use-se-list', required=False, action='store_true', default=False)
    parser.add_argument('--port', required=False, action='store', type=int, default=None)
    parser.add_argument('--username', default='admin', required=False, action='store')
    parser.add_argument('--password', default='58NFaGDJm(PJH0G', required=False, action='store')
    args = parser.parse_args()

    try:
        se_list = []
        if args.se:
            se_list.extend(args.se)
        elif args.use_se_list:
            if os.path.exists(SE_LIST_FILE):
                with open(SE_LIST_FILE, 'r') as fp:
                    se_yaml = yaml.load(fp.read())
                    se_list.extend(se_yaml.values())
        else:
            se_list = find_ses_using_reverse_tunnel()

        if not se_list:
            print 'No SEs to sync current controller secure channel certificate.'
        else:
            execute(sync_se_entries, args.username, args.password, args.port,
                    hosts=se_list)
    except (Exception, SystemExit) as ex:
        print 'Connect SE IP failed [%s]: %s' % (ex, traceback.format_exc())
        raise ex

