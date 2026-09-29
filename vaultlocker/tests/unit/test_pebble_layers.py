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

"""
test_pebble_layers
----------------------------------

Tests for `pebble_layers` module.
"""

import subprocess
from unittest import mock

from vaultlocker import pebble_layers
from vaultlocker.tests.unit import base

LAYER_PATH = '/data/pebble/layers/100-vaultlocker-decrypt-test-uuid.yaml'
LOCK_PATH = '/data/pebble/.vaultlocker-layers.lock'


class TestPebbleLayers(base.TestCase):

    def test_layer_label(self):
        self.assertEqual(
            'vaultlocker-decrypt-test-uuid',
            pebble_layers.layer_label('test-uuid'),
        )

    def test_service_name(self):
        self.assertEqual(
            'decrypt-test-uuid',
            pebble_layers.service_name('test-uuid'),
        )

    def test_render_layer(self):
        layer = pebble_layers.render_layer(
            'test-uuid', '/path/to/conf', 1234,
        )

        self.assertIn('decrypt-test-uuid:', layer)
        self.assertIn(
            'command: vaultlocker --retry 1234 --config '
            '/path/to/conf decrypt test-uuid',
            layer,
        )
        self.assertIn('startup: enabled', layer)
        self.assertIn('on-success: ignore', layer)
        self.assertIn('on-failure: restart', layer)
        self.assertIn('backoff-delay: 5s', layer)
        self.assertIn('backoff-limit: 30s', layer)

    def test_pebble_dir_defaults(self):
        with mock.patch.dict(pebble_layers.os.environ, {}, clear=True):
            self.assertEqual(
                pebble_layers.DEFAULT_PEBBLE_DIR,
                pebble_layers.pebble_dir(),
            )

    def test_pebble_dir_from_environment(self):
        with mock.patch.dict(
                pebble_layers.os.environ, {'PEBBLE': '/data/pebble'}):
            self.assertEqual('/data/pebble', pebble_layers.pebble_dir())

    @mock.patch.object(pebble_layers.fcntl, 'flock')
    @mock.patch.object(pebble_layers.os, 'listdir', return_value=[])
    @mock.patch.object(pebble_layers.os, 'replace')
    @mock.patch.object(pebble_layers.os, 'makedirs')
    @mock.patch.object(pebble_layers.subprocess, 'run')
    @mock.patch('builtins.open', new_callable=mock.mock_open)
    def test_register_boot_unlock(
            self, _open, _run, _makedirs, _replace, _listdir, _flock):
        with mock.patch.dict(
                pebble_layers.os.environ, {'PEBBLE': '/data/pebble'}):
            pebble_layers.register_boot_unlock(
                'test-uuid', '/path/to/conf', 1234,
            )

        _makedirs.assert_called_once_with(
            '/data/pebble/layers', exist_ok=True,
        )
        self.assertEqual(
            [
                mock.call(LOCK_PATH, 'a+b'),
                mock.call(LAYER_PATH + '.tmp', 'w', encoding='utf-8'),
            ],
            _open.call_args_list,
        )
        _flock.assert_called_once_with(
            _open.return_value, pebble_layers.fcntl.LOCK_EX,
        )
        _open.return_value.write.assert_called_once()
        _replace.assert_called_once_with(
            LAYER_PATH + '.tmp', LAYER_PATH,
        )
        self.assertEqual(
            [
                mock.call(
                    ['pebble', 'add', '--combine',
                     'vaultlocker-decrypt-test-uuid', LAYER_PATH],
                    check=True, capture_output=True,
                ),
                mock.call(
                    ['pebble', 'replan', '--no-wait'],
                    check=True, capture_output=True,
                ),
            ],
            _run.call_args_list,
        )

    @mock.patch.object(pebble_layers.fcntl, 'flock')
    @mock.patch.object(pebble_layers.os, 'listdir', return_value=[])
    @mock.patch.object(pebble_layers.os, 'replace')
    @mock.patch.object(pebble_layers.os, 'makedirs')
    @mock.patch.object(pebble_layers.subprocess, 'run')
    @mock.patch('builtins.open', new_callable=mock.mock_open)
    def test_register_boot_unlock_propagates_replan_failure(
            self, _open, _run, _makedirs, _replace, _listdir, _flock):
        _run.side_effect = [
            None,
            subprocess.CalledProcessError(
                returncode=1, cmd='pebble replan --no-wait'
            ),
        ]

        with mock.patch.dict(
                pebble_layers.os.environ, {'PEBBLE': '/data/pebble'}):
            with self.assertRaises(subprocess.CalledProcessError):
                pebble_layers.register_boot_unlock(
                    'test-uuid', '/path/to/conf', 1234,
                )

        _replace.assert_called_once_with(
            LAYER_PATH + '.tmp', LAYER_PATH,
        )
        self.assertEqual(2, _run.call_count)

    @mock.patch.object(pebble_layers.fcntl, 'flock')
    @mock.patch.object(pebble_layers.os, 'listdir', return_value=[])
    @mock.patch.object(pebble_layers.os, 'replace')
    @mock.patch.object(pebble_layers.os, 'makedirs')
    @mock.patch.object(pebble_layers.subprocess, 'run')
    @mock.patch('builtins.open', new_callable=mock.mock_open)
    def test_register_boot_unlock_propagates_add_failure(
            self, _open, _run, _makedirs, _replace, _listdir, _flock):
        _run.side_effect = subprocess.CalledProcessError(
            returncode=1, cmd='pebble add',
        )

        with mock.patch.dict(
                pebble_layers.os.environ, {'PEBBLE': '/data/pebble'}):
            with self.assertRaises(subprocess.CalledProcessError):
                pebble_layers.register_boot_unlock(
                    'test-uuid', '/path/to/conf', 1234,
                )

        _run.assert_called_once_with(
            ['pebble', 'add', '--combine',
             'vaultlocker-decrypt-test-uuid', LAYER_PATH],
            check=True, capture_output=True,
        )


class TestLayerPath(base.TestCase):
    """Tests for numeric layer prefix allocation."""

    def test_allocates_first_prefix(self):
        with mock.patch.object(pebble_layers.os, 'listdir', return_value=[]):
            path = pebble_layers._layer_path(
                '/data/pebble/layers', 'vaultlocker-decrypt-u',
            )

        self.assertEqual(
            '/data/pebble/layers/100-vaultlocker-decrypt-u.yaml', path,
        )

    def test_allocates_next_prefix(self):
        names = ['100-a.yaml', 'notanumber.txt', '101-b.yaml']
        with mock.patch.object(
                pebble_layers.os, 'listdir', return_value=names):
            path = pebble_layers._layer_path(
                '/data/pebble/layers', 'vaultlocker-decrypt-u',
            )

        self.assertEqual(
            '/data/pebble/layers/102-vaultlocker-decrypt-u.yaml', path,
        )

    def test_reuses_existing_label(self):
        names = ['100-a.yaml', '101-vaultlocker-decrypt-u.yaml']
        with mock.patch.object(
                pebble_layers.os, 'listdir', return_value=names):
            path = pebble_layers._layer_path(
                '/data/pebble/layers', 'vaultlocker-decrypt-u',
            )

        self.assertEqual(
            '/data/pebble/layers/101-vaultlocker-decrypt-u.yaml', path,
        )
