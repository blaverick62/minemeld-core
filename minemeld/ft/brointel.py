# Bro Intel Output Node
# 
# Extension for Minemeld that outputs IP and Domain IOCs directly to
# Bro Intel rules.

from __future__ import absolute_import

import logging
import ujson
import datetime
import netaddr

from . import base
from . import actorbase

LOG = logging.getLogger(__name__)


class BroIntelOutput(actorbase.ActorBaseFT):
	def __init__(self, name, chassis, config):
		super(BroIntelOutput, self).__init__(name, chassis, config)

	def configure(self):
		super(BroIntelOutput, self).configure()

		self.brointel_filepath = self.config.get('brointel_filepath', '/DIP/brointel/')
		if self.brointel_filepath[-1] != '/':
			self.brointel_filepath += '/'

	def initialize(self):
		pass

	def rebuild(self):
		pass

	def reset(self):
		pass

	def _parse_ip_indicators(self, indicators):
		ipRange = indicators.split('-')
		if ipRange[0] == ipRange[1]:
			procIndicators = [netaddr.IPAddress(ipRange[0])]
			intelType = 'IPv4'
		else:
			procIndicators = netaddr.iprange_to_cidrs(ipRange[0], ipRange[1])
			intelType = 'CIDR'
		return procIndicators, intelType

	def _write_brointel_rules(self, message, source=None, indicator=None, value=None):
		now = datetime.datetime.now()
		d = datetime.datetime.today()
		day = d.strftime('%Y%m%d')

		fields = {
			'brointel_output_node': self.name,
			'message': message
		}

		intelTypes = {
			'md5': 'Intel::FILE_HASH',
			'IPv4': 'Intel::ADDR',
			'domain': 'Intel::DOMAIN',
			'CIDR': 'Intel:SUBNET'
		}

		if indicator is not None:
			fields['@indicator'] = indicator

		if source is not None:
			fields['@origin'] = source

		if value is not None:
			fields.update(value)

		if 'last_seen' in fields:
			last_seen = datetime.datetime.fromtimestamp(
					float(fields['last_seen'])/1000.0
			)
			fields['last_seen'] = last_seen.isoformat()+'Z'

		if 'first_seen' in fields:
			first_seen = datetime.datetime.fromtimestamp(
					float(fields['first_seen'])/1000.0
			)
			fields['first_seen'] = first_seen.isoformat()+'Z'

		# Join multiple sources into one string
		try:
			if fields['sources'] is not None:
				sources = ", ".join(fields['sources'])
			else:
				sources = ""
		except Exception as e:
			LOG.exception("Error parsing out sources field: \n\t" + e.message)
			raise

		details = "Confidence: " + fields['confidence']

		# Add Recorded Future Details
		if 'recordedfuture_evidencedetails' in fields:
			details = details + ', Details: ' + ", ".join(fields['recordedfuture_evidencedetails'])

		# Parse Indicators and Types into Tuples for writing
		if fields['type'] == "IPv4":
			procIndicators = self._parse_ip_indicators(fields['@indicator'])
		else:
			procIndicators = ([fields['@indicator']], fields['type'])


		try:
			if message == "update":
				with open("{}minemeld-{}-{}.rules".format(self.brointel_filepath, fields['type'], day), 'a+') as f:
					for indivIndicator in procIndicators[0]:	
						f.write("{}\t{}\t{}\t{}\t-\n".format(
							fields['@indicator'],
							intelTypes[procIndicators[1]]
							sources,
							details
						)
					)
					self.statistics['message.sent'] += 1
		except Exception as e:
			LOG.exception("Error writing bro rules: \n\t" + e.message)
			raise

		

	@base._counting('update.processed')
	def filtered_update(self, source=None, indicator=None, value=None):
		self._write_brointel_rules(
			'update',
			source=source,
			indicator=indicator,
			value=value
		)

	@base._counting('withdraw.processed')
	def filtered_withdraw(self, source=None, indicator=None, value=None):
		self._write_brointel_rules(
			'withdraw',
			source=source,
			indicator=indicator,
			value=value
		)

	def length(self, source=None):
		return 0