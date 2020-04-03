#!/usr/bin/env python3

import sys
#import subprocess
import logging
import os, time
import base64
sys.path.append('lib')  # noqa

from ops.main import main
from ops.charm import CharmBase
from charms.templating.jinja2 import render
from ops.model import ActiveStatus, MaintenanceStatus, BlockedStatus, WaitingStatus
from fetch import apt_install, configure_sources, apt_update, apt_autoremove, apt_purge
from ops.framework import StoredState

from elasticbeats import (
    enable_beat_on_boot,
    get_package_candidate,
    push_beat_index,
    remove_beat_on_boot,
    render_without_context,
)

logger = logging.getLogger(__name__)


class FileBeatCharm(CharmBase):

    FILEBEAT_CONFIG = '/etc/filebeat/filebeat.yml'
    KUBE_CONFIG = '/root/.kube/config'
    LOGSTASH_SSL_CERT = '/etc/ssl/certs/filebeat-logstash.crt'
    LOGSTASH_SSL_KEY = '/etc/ssl/private/filebeat-logstash.key'
    state = StoredState()

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.install, self.on_install)
        self.framework.observe(self.on.stop, self.on_remove)
        self.framework.observe(self.on.config_changed, self.on_config_changed)
        self.framework.observe(self.on.reinstall_action, self.on_reinstall_action)
        self.framework.observe(self.beats_server.on.server_ready, self.on_beats_server_available)
        self.state.set_default(repo_sources_hash=None, repo_keys_hash=None, needs_reinstall=False, logstash_key=None, logstash_cert=None)

    def on_install(self, event):
        logger.info('Installing filebeat')
        sources = self.model.config.get('install_sources', '')
        keys = self.model.config.get('install_keys', '')
        self.state.repo_details_hash = hash(sources + keys)
        configure_sources(update=True, sources_var=sources, keys_var=keys)
        apt_install('filebeat')
        self.unit.status = ActiveStatus("Filebeat is installed")

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

        self.manage_filebeat_logstash_ssl()

        pass #TODO

    def manage_filebeat_logstash_ssl(self):
        """Manage the ssl cert/key that filebeat uses to connect to logstash.
            Create the cert/key files when both logstash_ssl options have been set;
            update when either config option changes; remove if either gets unset.
            """
        logstash_ssl_cert = self.model.config['logstash_ssl_cert']
        logstash_ssl_key = self.model.config['logstash_ssl_key']
        if logstash_ssl_cert and logstash_ssl_key:
            cert = base64.b64decode(logstash_ssl_cert).decode('utf8')
            key = base64.b64decode(logstash_ssl_key).decode('utf8')

            if cert != self.state.logstash_cert:
                render(template='{{ data }}',
                       context={'data': cert},
                       target=self.LOGSTASH_SSL_CERT, perms=0o444)

            if key != self.state.logstash_key:
                render(template='{{ data }}',
                       context={'data': key},
                       target=self.LOGSTASH_SSL_KEY, perms=0o400)
            else:
                if not logstash_ssl_cert and os.path.exists(self.LOGSTASH_SSL_CERT):
                    os.remove(self.LOGSTASH_SSL_CERT)
                if not logstash_ssl_key and os.path.exists(self.LOGSTASH_SSL_KEY):
                    os.remove(self.LOGSTASH_SSL_KEY)

    def on_beats_server_available(self, event):
        """Create the Filebeat index in Elasticsearch.
            Once elasticsearch is available, make 5 attempts to create a filebeat
            index. Set appropriate charm status so the operator knows when ES is
            configured to accept data.
            """
        hosts = self.beats_server.socket_addresses[0]
        for host in hosts:
            host_string = "{}:{}".format(host['host'], host['port'])

        max_attempts = 5
        for i in range(1, max_attempts):
            if push_beat_index(elasticsearch=host_string,
                               service='filebeat', fatal=False):
                logger.info('Filebeat.index.pushed')
                self.unit.status = ActiveStatus("Filebeat ready")
                break
            else:
                msg = "Attempt {} to push filebeat index failed (retrying)".format(i)
                self.unit.status = WaitingStatus(msg)
                time.sleep(i * 30)  # back off 30s for each attempt
        else:
            msg = "Failed to push filebeat index to http://{}".format(host_string)
            self.unit.status = BlockedStatus(msg)

    def on_remove(self, event):
        logger.info('Removing filebeat')
        apt_autoremove('filebeat')
        self.unit.status = MaintenanceStatus('Removing filebeat')


if __name__ == '__main__':
    main(FileBeatCharm)
