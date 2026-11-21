import hashlib, json, sys, urllib.request
def get(url, accept=None, token=None):
    headers={'User-Agent':'eidbridge-pr31-validation'}
    if accept: headers['Accept']=accept
    if token: headers['Authorization']='Bearer '+token
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=15) as r:
        return r.headers, r.read()
def action(repo, tag):
    base=f'https://api.github.com/repos/{repo}'
    _, raw=get(f'{base}/git/ref/tags/{tag}')
    obj=json.loads(raw)['object']
    while obj['type']=='tag':
        _, raw=get(obj['url'])
        tag=json.loads(raw).get('tag',tag)
        obj=json.loads(raw)['object']
    assert obj['type']=='commit',obj
    return obj['sha']
def image(name, ref):
    _, raw = get(f'https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/{name}:pull')
    token=json.loads(raw)['token']
    accept='application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json'
    headers, raw=get(f'https://registry-1.docker.io/v2/library/{name}/manifests/{ref}',accept,token)
    digest='sha256:'+hashlib.sha256(raw).hexdigest()
    assert digest==headers['Docker-Content-Digest']
    platforms={(m['platform']['os'],m['platform']['architecture']) for m in json.loads(raw)['manifests']}
    assert {('linux','amd64'),('linux','arm64')} <= platforms
    return digest
if __name__ == '__main__':
    kind, name, ref = sys.argv[1:]
    print(name,ref, (action if kind=='action' else image)(name,ref))
