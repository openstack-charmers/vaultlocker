# -*- coding: utf-8 -*-

# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import logging
import subprocess

logger = logging.getLogger(__name__)


def enable(service_name):
    """Enable a systemd unit

    :param: service_name: Name of the service to enable.
    """
    logging.info('Enabling systemd unit for {}'.format(service_name))
    cmd = ['systemctl', 'enable', service_name]
    subprocess.check_call(cmd)
