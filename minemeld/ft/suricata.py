# Suricata Output Node

from __future__ import absolute_import

import logging
import ujson
import datetime

from . import base
from . import actorbase

LOG = logging.getLogger(__name__)


class SuricataOutput(actorbase.ActorBaseFT):
	def __init__(self, name, chassis, config):
		super(SuricataOutput, self).__init__(name, chassis, config)

	def configure(self):
		super(SuricataOutput, self).configure()

		self.suricata_filepath = self.config.get('suricata_filepath', '/DIP/suricata/')

	def initialize(self):
		pass

	def rebuild(self):
		pass

	def reset(self):
		pass

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
			if len(fields['sources'] <= 1):
				sources = fields['sources'][0]
			else:
				sources = ", ".join(fields['sources'])
		except Exception as e:
			LOG.exception("Error parsing out sources field: \n\t" + e)
			raise

		if 'recordedfuture_evidencedetails' in fields:
			sources = sources + ': ' + ", ".join(fields['recordedfuture_evidencedetails'])

		try:
			with open(self.suricata_filepath + 'minemeld-' + day + '.rules', 'a+') as f:
				f.write("alert ip $HOME_NET any -> {} any (msg:\"{}. Confidence: {}\"; classtype:trojan-activity; sid:{}; rev:1;)\n".format(
					fields['@indicator'],
					sources,
					fields['confidence'],
					self.statistics['message.sent']
					)
				)
		except Exception as e:
			LOG.exception("Error writing suricata rules: \n\t" + e)
			raise

		self.statistics['message.sent'] += 1

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