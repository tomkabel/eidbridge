# Contributing to eidbridge

Thank you for helping. Read the [legal stance](docs/legal.md) first: eidbridge is unofficial, and every contribution must keep it clean-room and permissively licensed.

## Rules

1. **Sign off every commit** with the [Developer Certificate of Origin](https://developercertificate.org/): `git commit -s`. CI rejects pull requests with unsigned commits.
2. **Clean room.** Implement from published specifications. Never copy from LGPL-licensed demo applications or from unlicensed documentation; link to them instead. Vendor code samples are not reused.
3. **Permissive dependencies only.** New dependencies need an MIT, BSD, Apache-2.0, ISC or similar license and must appear in the `go-licenses` report. Prefer the standard library.
4. **No personal data.** Fixtures use synthetic or published demo test identities only. Never commit real personal codes, certificates of real people, session secrets or credentials. Never log identity data, at any level.
5. **Test first.** Add a failing test, then the behavior. Every verification step needs a negative test.
6. **Neutral names.** Scheme names never appear in package, image or module names.
7. **Spec pins are metadata.** Files under `docs/spec-pins/` hold links, versions, dates and hashes only.

## Checks

```sh
make check   # gofmt, go vet, go test -race, licenses, spec-pins, arch trace
```

## Security issues

Report privately; see [SECURITY.md](SECURITY.md).
