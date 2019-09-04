# ICOAST input node
from __future__ import absolute_import

import logging
import os
import ujson
import yaml
import netaddr
import netaddr.core

from . import csv

LOG = logging.getLogger(__name__)

class LocalICOAST(csv.CSVFT):
	def configure(self):
		super(LocalICOAST, self).configure()

		self.source_name = 'icoast.localicoast'
		self.confidence = self.config.get('confidence', 95)

	def _process_item(self, row):
		row.pop(None, None)

		result = {}
		LOG.debug("%s - processing item: %s",
			self.name, str(row))
		indicator = row.get('value', '')
		if indicator == '':
			LOG.debug("%s - unable to parse ICOAST indicator: %s",
				self.name, indicator)
			return []

		indicatorType = row.get('type', '')
		if indicatorType == '':
			LOG.info("%s - unable to parse ICOAST indicator type: %s",
				self.name, indicatorType)
			return []

		if indicatorType == "ip-src|port":
			indSpl = indicator.split('|')
			indicator = indSpl[0]

		typeMatch = {
			'hostname': 'domain',
			'ip-dst': 'IPv4',
			'sha1': 'sha1',
			'sha256': 'sha256',
			'md5': 'md5',
			'ip-src|port': 'IPv4',
			'url': 'url',
			'domain': 'domain'
		}

		if indicatorType not in typeMatch:
			LOG.info("%s - invalid ICOAST type: %s",
				self.name, indicatorType)
			return[]
		else:
			result['type'] = typeMatch[indicatorType]

		eventDate = row.get('event_date', '')
		if eventDate == '':
			return []
		else:
			result['icoast_eventDate'] = eventDate

		eventId = row.get('event_id', '')
		if eventId == '':
			return []
		else:
			result['icoast_eventId'] = eventId

		return [[indicator, result]]

	def _build_iterator(self, now):
		return super(LocalICOAST, self)._build_iterator(now)

	@staticmethod
	def gc(name, config=None):
		csv.CSVFT.gc(name, config=config)