import tempfile
import unittest
from pathlib import Path

from ip_address_validation_claim_audit.audit import ROUTES, audit, evidence, matches
from ip_address_validation_claim_audit.phrases import GENERIC_NAMES, IPADDRESSVALIDATION, NOIPADDRESSVALIDATION


class AuditTests(unittest.TestCase):
    def test_phrases(self):
        self.assertEqual((len(set(IPADDRESSVALIDATION)), len(set(NOIPADDRESSVALIDATION)), len(set(GENERIC_NAMES))), (50, 24, 24))
        for phrase in IPADDRESSVALIDATION:
            with self.subTest(phrase=phrase):
                self.assertTrue(matches(phrase)[0])
        for phrase in NOIPADDRESSVALIDATION:
            with self.subTest(phrase=phrase):
                self.assertEqual(matches(phrase), ([], [phrase]))
        self.assertEqual(matches('```\nvalidate ip address\n```\n\n`check ip address`')[0], ['check ip address'])
        self.assertEqual(matches("doesn't validate ip-address"), ([], ['does not validate ip address']))

    def test_library_routes(self):
        modules = {'django': 'django.core.validators', 'pydantic': 'pydantic', 'netaddr': 'netaddr', 'IPy': 'IPy', 'validators': 'validators', 'ipaddress': 'ipaddress'}
        for module, names in ROUTES.items():
            for name in names:
                with self.subTest(module=module, name=name):
                    self.assertTrue(evidence(f'import {modules[module]} as lib\nlib.{name}()'))
                    self.assertTrue(evidence(f'from {modules[module]} import {name} as alias\nalias()'))
                    self.assertFalse(evidence(f'{name}()'))
                    self.assertFalse(evidence(f'unknown.{name}()'))
        self.assertTrue(evidence('from netaddr.ip import IPAddress as a\na()'))
        self.assertTrue(evidence('from pydantic.networks import IPvAnyAddress as a\na()'))

    def test_generic_and_shadowing(self):
        for name in GENERIC_NAMES:
            with self.subTest(name=name):
                self.assertTrue(evidence(f'obj.{name}()'))
                self.assertTrue(evidence(f'from package import {name} as f\nf()'))
                self.assertFalse(evidence(f'{name}()'))
                self.assertFalse(evidence(f'def {name}(): pass\nobj.{name}()'))
        self.assertFalse(evidence('import validators as v\nv = other\nv.ipv4()'))
        self.assertFalse(evidence('import validators as v\nwith manager() as v: pass\nv.ipv4()'))
        self.assertTrue(evidence('obj = factory()\nobj.validate_ip()'))

    def test_not_evidence(self):
        cases = ['import ipaddress', 'from pydantic import IPvAnyAddress\naddr: IPvAnyAddress', 'from ipaddress import IPv4Address\naddr: IPv4Address', 'import validators\nvalidators.domain()','import validators\nvalidators.hostname()', 'import validators\nvalidators.url()', 'import django.core.validators as v\nv.ip_address_validators()', 'import django.utils.ipv6 as v\nv.is_valid_ipv6_address()', 'import subprocess\nsubprocess.run(["validate ip address"])', '"validate ip address"', 'from ipaddress import ip_address\nip_address', 'def broken(:', 'mail.send()', 'sms.send()', 'email.validate()', 'phone.validate()', 'password.strength()', 'auth.login()', 'extract.address()', 'barcode.decode()', 'qr.decode()', 'value.is_private', 'value.is_global', 'value.is_reserved']
        cases += [f'import socket\nsocket.{x}()' for x in ('inet_aton','inet_pton','inet_ntoa','inet_ntop','gethostbyname','gethostbyname_ex','getaddrinfo')]
        cases += [f'import re\nre.{x}(r"[0-9.]+", value)' for x in ('match','search','fullmatch')]
        cases += ['import dns.resolver\ndns.resolver.query()']
        for case in cases:
            with self.subTest(case=case): self.assertFalse(evidence(case))

    def test_findings_and_discovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'README.md').write_text('validate ip address')
            self.assertEqual(audit(root)['findings'][0]['severity'], 'HIGH')
            (root/'tests').mkdir()
            (root/'tests/test_x.py').write_text('import ipaddress\nipaddress.ip_address()')
            self.assertEqual(audit(root)['findings'][0]['severity'], 'MEDIUM')
            (root/'app.py').write_text('import ipaddress\nipaddress.ip_address()')
            self.assertEqual(audit(root)['findings'], [])
            (root/'README.md').write_text('no ip address validation')
            self.assertEqual(audit(root)['findings'][0]['severity'], 'HIGH')
            self.assertEqual(audit(root, ['app.py'])['findings'], [])

    def test_cli(self):
        from ip_address_validation_claim_audit.__main__ import main
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(main(['audit', tmp]), 0)
            (Path(tmp)/'README.md').write_text('validate ip address')
            self.assertEqual(main(['audit', tmp]), 2)
            self.assertEqual(main(['audit', tmp, '--ignore', 'README.md']), 0)
            self.assertEqual(main(['audit', tmp+'/missing']), 1)
