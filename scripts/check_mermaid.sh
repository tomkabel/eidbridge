#!/bin/sh
# Render every mermaid block in the given Markdown files; fail on a parse error.
set -eu
tmp=$(mktemp -d)
printf '{"args":["--no-sandbox"]}' > "$tmp/p.json"
n=0
for f in "$@"; do
  python3 -c "
import re,sys
d=open(sys.argv[1]).read()
for i,m in enumerate(re.findall(r'(?:~~~|\`\`\`)mermaid\n(.*?)(?:~~~|\`\`\`)',d,re.S)):
    open(sys.argv[2]+'/%s-%d.mmd'%(sys.argv[1].replace('/','_'),i),'w').write(m)
" "$f" "$tmp"
done
for m in "$tmp"/*.mmd; do
  [ -e "$m" ] || continue
  npx --yes @mermaid-js/mermaid-cli -p "$tmp/p.json" -i "$m" -o "$m.svg" >/dev/null
  n=$((n+1))
done
echo "mermaid: $n diagram(s) rendered"
