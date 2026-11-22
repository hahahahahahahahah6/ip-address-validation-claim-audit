"""Offline analysis of documentation and Python source."""
import ast
import os
import re
from pathlib import Path

from .phrases import GENERIC_NAMES, IPADDRESSVALIDATION, NOIPADDRESSVALIDATION

ROUTES = {
    'ipaddress': {'ip_address', 'ip_network', 'ip_interface', 'IPv4Address', 'IPv6Address', 'IPv4Network', 'IPv6Network', 'IPv4Interface', 'IPv6Interface'},
    'validators': {'ipv4', 'ipv6'},
    'netaddr': {'IPAddress', 'IPNetwork', 'valid_ipv4', 'valid_ipv6'},
    'IPy': {'IP'},
    'django': {'validate_ipv4_address', 'validate_ipv6_address', 'validate_ipv46_address'},
    'pydantic': {'IPvAnyAddress', 'IPvAnyInterface', 'IPvAnyNetwork'},
}
DIRECT = {f'{module}.{name}' for module, names in ROUTES.items() for name in names if module != 'django'}
DIRECT |= {f'netaddr.ip.{name}' for name in ('IPAddress', 'IPNetwork')}
DIRECT |= {f'pydantic.networks.{name}' for name in ROUTES['pydantic']}
DIRECT |= {f'django.core.validators.{name}' for name in ROUTES['django']}


def normalize(text):
    return ' '.join(text.lower().replace("n't", ' not').replace('-', ' ').split())


def prose(text):
    lines, fence = [], None
    for line in text.splitlines():
        match = re.match(r'^ {0,3}(`{3,}|~{3,})', line)
        if fence:
            if match and match.group(1)[0] == fence[0] and len(match.group(1)) >= len(fence) and not line[match.end():].strip():
                fence = None
            continue
        if match:
            fence = match.group(1)
            lines.append('')
        else:
            lines.append(line)
    return '\n'.join(lines)


def matches(text):
    found_yes, found_no = [], []
    for para in re.split(r'\n\s*\n', prose(text)):
        value = normalize(para)
        for phrases, found in ((NOIPADDRESSVALIDATION, found_no), (IPADDRESSVALIDATION, found_yes)):
            for phrase in sorted(phrases, key=lambda x: (-len(x), x)):
                pattern = r'(?<!\w)' + re.escape(phrase) + r'(?!\w)'
                if re.search(pattern, value):
                    found.append(phrase)
                    value = re.sub(pattern, ' ', value)
    return found_yes, found_no


def evidence(source):
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return False
    imports, definitions, bound = {}, set(), set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            definitions.add(node.name)
        elif isinstance(node, ast.Import):
            for item in node.names:
                imports[item.asname or item.name.split('.')[0]] = item.name if item.asname else item.name.split('.')[0]
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for item in node.names:
                imports[item.asname or item.name] = node.module + '.' + item.name
        targets = []
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target] if node.value is not None else []
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            targets = [item.optional_vars for item in node.items if item.optional_vars]
        for target in targets:
            bound.update(n.id for n in ast.walk(target) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store))
    shadow = definitions | (bound & imports.keys())
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name):
            resolved = imports.get(func.id, '')
            if func.id not in shadow and resolved.rsplit('.', 1)[-1] not in definitions and (resolved in DIRECT or resolved.rsplit('.', 1)[-1] in GENERIC_NAMES):
                return True
        elif isinstance(func, ast.Attribute):
            attr = func.attr
            if attr in definitions:
                continue
            base = func.value
            while isinstance(base, ast.Attribute):
                base = base.value
            if isinstance(base, ast.Name) and base.id in shadow:
                continue
            if attr in GENERIC_NAMES:
                return True
            if not isinstance(base, ast.Name):
                continue
            origin = imports.get(base.id, '')
            for module, names in ROUTES.items():
                if attr not in names:
                    continue
                if module == 'django':
                    ok = origin in ('django', 'django.core.validators')
                else:
                    ok = origin == module or origin.startswith(module + '.')
                if ok:
                    return True
    return False


def audit(root, ignores=()):
    root = Path(root)
    if not root.is_dir() or root.is_symlink() or not os.access(root, os.R_OK | os.X_OK):
        raise OSError('root is not a readable directory')
    docs, prod, tests = [], [], []
    prefixes = [x.replace('\\', '/').strip('/') for x in ignores]
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=lambda e: (_ for _ in ()).throw(e)):
        parent = Path(directory)
        def ignored(path):
            rel = path.relative_to(root).as_posix()
            return any(rel == x or rel.startswith(x + '/') for x in prefixes if x)
        dirs[:] = sorted(d for d in dirs if not (parent / d).is_symlink() and not ignored(parent / d))
        for name in sorted(files):
            path = parent / name
            if path.is_symlink() or ignored(path):
                continue
            rel = path.relative_to(root)
            if (rel == Path('README.md') or ('docs' in rel.parts and path.suffix == '.md')):
                docs.append((str(rel), path.read_text(encoding='utf-8')))
            if path.suffix == '.py' and not any(x in rel.parts for x in ('fixtures', 'docs', 'examples')):
                is_test = 'tests' in rel.parts or name.startswith('test_') or name.endswith('_test.py')
                if evidence(path.read_text(encoding='utf-8')):
                    (tests if is_test else prod).append(str(rel))
    yes, no = [], []
    for path, content in docs:
        y, n = matches(content)
        yes.extend({'path': path, 'phrase': x} for x in y)
        no.extend({'path': path, 'phrase': x} for x in n)
    findings = []
    if yes and not prod:
        findings.append({'id': 'documented-ip-address-validation-claim-false', 'severity': 'MEDIUM' if tests else 'HIGH', 'claims': yes})
    if no and prod:
        findings.append({'id': 'documented-no-ip-address-validation-claim-false', 'severity': 'HIGH', 'claims': no})
    return {'findings': findings, 'production_evidence': prod, 'test_evidence': tests, 'claims': yes, 'denials': no}
