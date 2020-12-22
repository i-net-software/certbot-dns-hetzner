"""DNS Authenticator for Hetzner DNS."""
import requests

import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

from certbot_dns_hetzner.hetzner_client import \
    _MalformedResponseException, \
    _HetznerClient, \
    _RecordNotFoundException, \
    _ZoneNotFoundException, _NotAuthorizedException

TTL = 60


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Hetzner
    This Authenticator uses the Hetzner DNS API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record (if you are using Hetzner for DNS).'

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=60)
        add('credentials', help='Hetzner credentials INI file.')

    def more_info(self):  # pylint: disable=missing-function-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Hetzner API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'Hetzner credentials INI file',
            {
                'api_token': 'Hetzner API Token from \'https://dns.hetzner.com/settings/api-token\'',
            }
        )

    def _perform(self, domain, validation_name, validation):
        client = self._get_hetzner_client()
        formated_name = self._fqdn_format(validation_name)

        try:
            try:
                # check if a record exists - and if so update it with the additional value
                zone_id = client.get_zone_id_by_domain(domain)
                record_id = client.get_record_id_by_name(zone_id, formated_name)
                record_value = client.get_record_value_by_name(zone_id, formated_name)

                client.update_record(
                    domain,
                    record_id,
                    "TXT",
                    formated_name,
                    "\\n".join([record_value, validation]),
                    TTL
                )

            except (
                    _RecordNotFoundException
            ) as exception:
                # this is Ok - there is no record yet.
                client.add_record(
                    domain,
                    "TXT",
                    formated_name,
                    validation,
                    TTL
                )
        except (
                _ZoneNotFoundException,
                requests.ConnectionError,
                _MalformedResponseException,
                _NotAuthorizedException
        ) as exception:
            raise errors.PluginError(exception)

    def _cleanup(self, domain, validation_name, validation):
        client = self._get_hetzner_client()
        formated_name = self._fqdn_format(validation_name)

        try:
            # check if a record exists with multiple entries - and if so downgrade it, removeing the current value
            zone_id = client.get_zone_id_by_domain(domain)
            record_id = client.get_record_id_by_name(zone_id, formated_name)
            record_values = client.get_record_value_by_name(zone_id, formated_name).split("\n")

            if validation in record_values:
                record_values.remove(validation)

            if len(record_values) <= 1:
                client.delete_record_by_name(domain, formated_name)
            else:
                client.update_record(
                    domain,
                    record_id,
                    "TXT",
                    formated_name,
                    "\\n".join(record_values),
                    TTL
                )

        except (requests.ConnectionError, _NotAuthorizedException) as exception:
            raise errors.PluginError(exception)

    def _get_hetzner_client(self):
        return _HetznerClient(
            self.credentials.conf('api_token'),
        )

    @staticmethod
    def _fqdn_format(name):
        if not name.endswith('.'):
            return '{0}.'.format(name)
        return name
