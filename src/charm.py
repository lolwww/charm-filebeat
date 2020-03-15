#!/usr/bin/env python3

import sys
#import subprocess
import logging
import os
sys.path.append('lib')  # noqa

from ops.main import main
from ops.charm import CharmBase
from ops.model import ActiveStatus, MaintenanceStatus, BlockedStatus
from fetch import apt_install, configure_sources, apt_update, apt_autoremove, apt_purge
from ops.framework import StoredState

logger = logging.getLogger(__name__)


class FileBeatCharm(CharmBase):
    KUBE_CONFIG = '/root/.kube/config'
    state = StoredState()

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.install, self.on_install)
        self.framework.observe(self.on.stop, self.on_remove)
        self.framework.observe(self.on.config_changed, self.on_config_changed)
        self.framework.observe(self.on.reinstall_action, self.on_reinstall_action)
        self.state.set_default(repo_sources_hash=None, repo_keys_hash=None, needs_reinstall=False)

    def on_install(self, event):
        logger.info('Installing filebeat')
        sources = self.model.config.get('install_sources', '')
        keys = self.model.config.get('install_keys', '')
        self.state.repo_details_hash = hash(sources + keys)
        configure_sources(update=True, sources_var=sources, keys_var=keys)
        apt_install('filebeat')
        self.unit.status = ActiveStatus("Filebeat is installed")

    def on_remove(self, event):
        logger.info('Removing filebeat')
        apt_autoremove('filebeat')
        self.unit.status = MaintenanceStatus('Removing filebeat')

    def on_config_changed(self, event):
        sources = self.model.config.get('install_sources', '')
        keys = self.model.config.get('install_keys', '')
        new_repo_sources_hash = hash(sources)
        new_repo_keys_hash = hash(keys)
        if self.state.repo_sources_hash != new_repo_sources_hash:
            configure_sources(update=True, sources_var=sources, keys_var=keys)
            self.state.needs_reinstall = True
            msg = "Filebeat repo changed, use reinstall action to obtain a new version."
            self.unit.status = BlockedStatus(msg)
            return
        elif self.state.repo_keys_hash != new_repo_keys_hash:
            configure_sources(update=True, sources_var=sources, keys_var=keys)
        self.render_filebeat_template()

    def on_reinstall_action(self, event):
        if self.state.needs_reinstall:
            logger.info('Reinstalling filebeat')
            apt_purge('filebeat')
            apt_install('filebeat')
            self.state.needs_reinstall = False
            self.render_filebeat_template()

    def render_filebeat_template(self):
        """Create the filebeat.yaml config file.
            Renders the appropriate template for the major version of filebeat that
            is installed.
            """
        if self.model.config['kube_logs']:
            if os.path.exists(self.KUBE_CONFIG):
                msg = 'Collecting k8s metadata.'
            else:
                msg = ('kube_logs=True, but {} does not exist. '
                       'No k8s metadata will be collected.'.format(self.KUBE_CONFIG))
            logger.info(msg)


if __name__ == '__main__':
    main(FileBeatCharm)
