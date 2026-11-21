import pathlib, re, sys
root = pathlib.Path(sys.argv[1])
errors = []
for path in sorted((root / '.github/workflows').glob('*.y*ml')):
    for line in path.read_text().splitlines():
        if m := re.match(r'^\s*(?:-\s*)?uses:\s*([^\s#]+)', line):
            ref = m[1].strip('"\'')
            if not ref.startswith('./') and not re.search(r'@[0-9a-f]{40}$', ref):
                errors.append(f'{path.name}: {ref}')
for name in ('Dockerfile', 'Dockerfile.goreleaser'):
    for line in (root / name).read_text().splitlines():
        if m := re.match(r'^\s*FROM\s+(?:--\S+\s+)*(\S+)', line, re.I):
            if m[1] != 'scratch' and not re.search(r'@sha256:[a-f0-9]{64}$', m[1]):
                errors.append(f'{name}: {m[1]}')
dependabot = (root / '.github/dependabot.yml').read_text()
for ecosystem in ('docker', 'github-actions'):
    if not re.search(r'package-ecosystem: '+ecosystem+r'\s+directory: /(?:\s|$)', dependabot):
        errors.append(f'no root Dependabot coverage for {ecosystem}')
if errors:
    sys.exit('\n'.join(errors))
print('Workflow and image pin format and updater coverage passed')
