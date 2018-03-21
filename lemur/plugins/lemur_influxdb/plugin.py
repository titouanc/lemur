"""
.. module: lemur.plugins.lemur_influxdb.plugin
    :platform: Unix
    :copyright: (c) 2018 by Titouan Christophe., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Titouan Christophe <titouan.christophe@railnova.eu>
"""
import requests
from requests.exceptions import ConnectionError
from time import time

from flask import current_app
from lemur.plugins.bases.metric import MetricPlugin


class InfluxDBMetricPlugin(MetricPlugin):
    title = 'InfluxDB'
    slug = 'influxdb-metric'
    description = 'Adds support for sending key metrics to InfluxDB'
    version = '0.1.0'

    author = 'Titouan Christophe'
    author_url = 'https://github.com/titouanc'

    options = [
        {
            'name': 'influxdb_host',
            'type': 'str',
            'required': False,
            'help_message': 'If no host is provided localhost is assumed',
            'default': 'localhost'
        },
        {
            'name': 'influxdb_port',
            'type': 'int',
            'required': False,
            'default': 8086
        },
        {
            'name': 'influxdb_database',
            'type': 'str',
            'required': True,
        }
    ]

    def submit(self, metric_name, metric_type, metric_value, metric_tags=None, options=None):
        if not options:
            options = self.options

        current_app.logger.info("Ignoring metric type '%s' in InfluxDB",
                                metric_type)

        if not metric_tags:
            metric_tags = {}

        if not isinstance(metric_tags, dict):
            raise Exception(
                "Invalid Metric Tags for InfluxDB: Tags must be in dict format"
            )

        # Build the line we're about to send to influx
        timestamp = int(1000 * time())
        tags_text = ['%s=%s' % x for x in metric_tags.items()]
        tags_prefix = ','.join([metric_name] + tags_text)
        payload_fmt = "{tags} value={value} {timestamp}\n"

        host = self.get_option('influxdb_host', options)
        port = self.get_option('influxdb_port', options)
        dbname = self.get_option('influxdb_database', options)
        url_fmt = "http://{host}:{port}/write?db={dbname}"

        try:
            res = requests.post(
                url_fmt.format(host=host, port=port, dbname=dbname),
                data=payload_fmt.format(tags=tags_prefix,
                                        value=metric_value,
                                        timestamp=timestamp)
            )

            if res.status_code != 200:
                errmsg = "Failed to publish metric: {0}".format(res.content)
                current_app.logger.warning(errmsg)

        except ConnectionError:
            current_app.logger.warning(
                "InfluxDB: could not connect to server {host}:{port}".format(
                    host=host, port=port
                )
            )
