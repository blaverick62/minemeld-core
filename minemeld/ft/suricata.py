# Suricata Output Node
# 
# Extension for Minemeld that outputs IP and Domain IOCs directly to
# Snort/Suricata rules.

from __future__ import absolute_import

import logging
import ujson
import datetime
import netaddr

from . import base
from . import actorbase

LOG = logging.getLogger(__name__)


class SuricataOutput(actorbase.ActorBaseFT):
	def __init__(self, name, chassis, config):
		super(SuricataOutput, self).__init__(name, chassis, config)

	def configure(self):
		super(SuricataOutput, self).configure()

		self.suricata_filepath = self.config.get('suricata_filepath', '/DIP/suricata/')
		if self.suricata_filepath[-1] != '/':
			self.suricata_filepath += '/'

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
		else:
			procIndicators = netaddr.iprange_to_cidrs(ipRange[0], ipRange[1])
		return procIndicators

	def _write_suricata_rules(self, message, source=None, indicator=None, value=None):
		now = datetime.datetime.now()
		d = datetime.datetime.today()
		day = d.strftime('%Y%m%d')

		fields = {
			'suricata_output_node': self.name,
			'message': message
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

		try:
			if fields['sources'] is not None:
				sources = ", ".join(fields['sources'])
			else:
				sources = ""
		except Exception as e:
			LOG.exception("Error parsing out sources field: \n\t" + e.message)
			raise

		if 'recordedfuture_evidencedetails' in fields:
			sources = sources + ': ' + ", ".join(fields['recordedfuture_evidencedetails'])

		if fields['type'] == "IPv4":
			procIndicators = self._parse_ip_indicators(fields['@indicator'])

		try:
			if message == "update":
				with open("{}minemeld-{}-{}.rules".format(self.suricata_filepath, fields['type'], day), 'a+') as f:
					if fields['type'] == 'IPv4':
						for indivIndicator in procIndicators:	
							f.write("alert ip $HOME_NET any -> {} any (msg:\"{}. Confidence: {}\"; sid:{}; rev:1;)\n".format(
								indivIndicator,
								sources,
								fields['confidence'],
								self.statistics['message.sent']
								)
							)
					elif fields['type'] == "domain":
						f.write("alert dns $HOME_NET any -> any any (msg:\"{}. Confidence: {}\"; dns_query; content:{}; nocase; sid:{}; rev:1;)\n".format(
								sources,
								fields['confidence'],
								fields['@indicator'],
								self.statistics['message.sent']
								)
							)
					elif fields['type'] == "md5":
						f.write("{}\tIntel::FILE_HASH\t{}\t{}\t-\n".format(
								fields['@indicator'],
								sources,
								fields['confidence']
							)
						)

					self.statistics['message.sent'] += 1
		except Exception as e:
			LOG.exception("Error writing suricata rules: \n\t" + e.message)
			raise

		

	@base._counting('update.processed')
	def filtered_update(self, source=None, indicator=None, value=None):
		self._write_suricata_rules(
			'update',
			source=source,
			indicator=indicator,
			value=value
		)

	@base._counting('withdraw.processed')
	def filtered_withdraw(self, source=None, indicator=None, value=None):
		self._write_suricata_rules(
			'withdraw',
			source=source,
			indicator=indicator,
			value=value
		)

	def length(self, source=None):
		return 0