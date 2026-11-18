#!/usr/bin/env python3
"""Frozen independent BMAD coverage proxy, authored 2026-11-18.
Usage: python tools/verify_bmad_artifacts.py [--root PATH] [--research PATH]
Read-only checks. JSON stdout. Exit 0 PASS, 1 FAIL.
PROXY ONLY: presence, provenance, exact preservation, references and DAG are
checked; semantic completeness, implementation/security correctness, business
validity, legal applicability and actual user outcomes are not established.
"""
from pathlib import Path
import argparse,csv,hashlib,json,re,sys
from urllib.parse import unquote

FROZEN_HASHES = {'/home/notroot/Documents/eidbridge/_bmad-output/planning-artifacts/research/github-issues-2026-11-18.json': '1911b7540461f8d80a7fe5b94018b239fd67046091046b5452f9f95630091a98', '/home/notroot/research/competetive/_issues/eideasy/01-x509-hash-signed-request-objects.md': 'd31d28fcfd48c2cc5de03dc993eae9a84209c72749606b8593e7b3d687fdc855', '/home/notroot/research/competetive/_issues/eideasy/02-conformance-suite-and-reference-interop.md': 'dbd20e967e938a4491d77456692721222bb6a87b7fbfb7290b8a18d88d2fa328', '/home/notroot/research/competetive/_issues/eideasy/03-release-gated-verifier-deviation-table.md': '1dcffc98e1d38582fcb82e784bfc5bb6fd8755ff45ef20398b98ba2a3478a226', '/home/notroot/research/competetive/_issues/eideasy/04-verifier-scope-and-limits-statement.md': '5ab6758eb816a574f7ec08fbc7b1fb5e520db0279cbd3958e47339f5420179fe', '/home/notroot/research/competetive/_issues/eideasy/05-append-only-validation-audit-log.md': '4a8d70668e47b2112f1f8924e409eb75e5ad4e72bf46869e169e277906b86349', '/home/notroot/research/competetive/_issues/eideasy/06-rp-registration-record-and-registrar-export.md': 'd91c6038acbb43e7d0cb7d94779698004fe664d11a6645bdfd81601e8df5df48', '/home/notroot/research/competetive/_issues/eideasy/07-dpia-outline-and-ropa-template.md': '9a356c5202becf684c7d02791888f9aca668668639e2c1eb8039f9567e1aebea', '/home/notroot/research/competetive/_issues/eideasy/08-incident-runbook.md': 'c909ac78a9d47d3526b0c83932892d69c6d86473eee824f76c89ecdd402aa836', '/home/notroot/research/competetive/_issues/eideasy/09-production-deployment-guide.md': '4ac43cd0f0a34ec4bd59af8a658cce0c9088d16f58f436fec05ffc19406758d3', '/home/notroot/research/competetive/_issues/eideasy/10-release-artifacts-and-container-image.md': 'b8d25c04476127f44a3a325d03eb00d12a2276fb62201e932c013c97d3f46a11', '/home/notroot/research/competetive/_issues/eideasy/11-age-verification-integration-guide.md': '92c2c85f5280b2ce62bc0a83786e013228ec6e2f5b8be51bf7f05c1b1a82f453', '/home/notroot/research/competetive/_issues/eideasy/12-multiple-rp-identities-per-instance.md': 'c783b5d7ce364d27a993bcf0f72a7cc4fa94bc754a83f04f86882d0151e5699b', '/home/notroot/research/competetive/_issues/eideasy/13-openid4vp-to-oidc-bridge.md': '08a35fb8e14b69243bde50143683d47d786f1c2a25a03920c6bf0e1fc0bf95a3', '/home/notroot/research/competetive/_issues/eideasy/14-plain-pid-presentation-path.md': '3fd7cc1c944242c941035b233d82077d62e2883688453b403617c96ba4e6d92e', '/home/notroot/research/competetive/_issues/eideasy/15-lotl-trust-list-refresh.md': '5fd9a7e14a2ad797584724749199977993a1a9c9809bd86fa4d38e93312494b3', '/home/notroot/research/competetive/_issues/eideasy/16-pkcs11-key-backend.md': '549c6b17b32a6f0fad6dff8e6839f34a289f4da6e4387af2910e2fc81ad6711d', '/home/notroot/research/competetive/_issues/eideasy/17-cms-plugin-wallet-acceptance.md': 'a947f939338c4ddec11acbe629a9ed03dfbd23ac9696a2d1e9d29d259c9e4383', '/home/notroot/research/competetive/_issues/eideasy/18-wallet-authorised-remote-signing.md': '6afb0ab1493e2fabb64b2996743fe99e90d295b475d5464ae7d225f5ee501c08', '/home/notroot/research/competetive/_issues/glazer/01-fix-chunked-response-hang.md': 'fcf7e4e214454fbdde1b2b5ad740bf31bc8ad2c0342ad153080a0c0c27b54639', '/home/notroot/research/competetive/_issues/glazer/02-rfc3161-stamp.md': 'f56d222a28b4354ab11220c4725d205eb86bfa6beb03429320750a8caa6d6473', '/home/notroot/research/competetive/_issues/glazer/03-verify-command.md': 'e5a05641b40b37e465e3176662f0a0c8fe268a840f911e95caba434254c727aa', '/home/notroot/research/competetive/_issues/glazer/04-verification-docs-demo-case.md': '737e2951a1486ac2e85c73c8c4cd4f84121a76e0237e3c52c7b675d3d38cf137', '/home/notroot/research/competetive/_issues/glazer/05-refusal-records.md': '07c34150b0dff43406332b832acfde96d930c8acfdab6b00dcffc8ca275e1ed9', '/home/notroot/research/competetive/_issues/glazer/06-case-json-metadata.md': 'ce3244575b249f12e5d990e90208153d68d51d8d54e90a6e03bffcbc37bbab21', '/home/notroot/research/competetive/_issues/glazer/07-redact-flag.md': 'ee14e9aa41b1319ee8f2083eec68cc273ba85f6882985bc975de6ffe01aea1d4', '/home/notroot/research/competetive/_issues/glazer/08-capture-retention.md': '11301d1852de77bcd5b1763b97c69778e277596a318806799e4908c54954ba01', '/home/notroot/research/competetive/_issues/glazer/09-capture-start-warning.md': 'e8c505dd73dad93257b9ae88194d211c6e9e8d682340e23a3b580cf68f5bf9e6', '/home/notroot/research/competetive/_issues/glazer/10-operator-obligations-docs.md': '39e0570b2396d0a3192206ef1803fbdba1946b530541bb9cfc12919055b6b3e7', '/home/notroot/research/competetive/_issues/glazer/11-mcp-server.md': 'ef9a9b4d554ea1daef056fff1fe95a4614d42c6b10cd8d495fe69d64d5c1c3e9', '/home/notroot/research/competetive/_issues/glazer/12-mcp-safety-policy.md': 'a60097928b343a5a8e558f6a2e9d2b78e65fb5de8cf05d82c00bfb1ac457b7b1', '/home/notroot/research/competetive/_issues/glazer/13-mcp-agpl-source-offer.md': 'e3f3de0cfe0f30e12b8ec480768fe3737c9948821ea395119586c05f1d6243de', '/home/notroot/research/competetive/_issues/glazer/14-fingerprint-coverage-metrics.md': '765dea9fa74eb5cb7b2d733c6b1fe2b24f33a91b208a8a8ffd4a70b5a7245c8a', '/home/notroot/research/competetive/_issues/glazer/15-homebrew-release-verification.md': '298bdd76ab8bd6b7e9c5cc247534ede48e6e875e93b766c24da382c7d9d8f8e5', '/home/notroot/research/competetive/_issues/glazer/16-capture-encryption-at-rest.md': '732721d02e933f4f1e864c32e5ac9f7cf7deabc8571037ca7440dde345c42a84', '/home/notroot/research/competetive/_issues/glazer/17-per-case-mitm-ca.md': '83864bea41160f1eb58c38a875a5a7f6e2f12b2c290b46066a69a076ef4c8fb5', '/home/notroot/research/competetive/_issues/glazer/18-record-upstream-cert-chain.md': 'be9c2a0dfb699dacf4a26bbf7b2483a795df244b3289d2f0a04663e597a4b695', '/home/notroot/research/competetive/_issues/glazer/19-warc-export.md': 'a387be9d65d12cd10f8cfed6078aa29be6158f14e7b9d0b4bb1a769bbbe897f1', '/home/notroot/research/competetive/_issues/glazer/20-enrichment-broker.md': '5eec4291b899b66063b528b810e73416e9f7caa224f700dc9978c703496450f7', '/home/notroot/research/competetive/_issues/manyfaces/21-case-scoped-profiles.md': '92429943ed721741fd2f434e2fa46711454b2c81cad2fd0239bbb1eeafa5329e', '/home/notroot/research/competetive/_issues/manyfaces/22-case-screenshots.md': '55d568dd39151c655a8816319dbf55a52d3f84a8d1a0eecac5b5c9d26aba2998', '/home/notroot/research/competetive/_issues/manyfaces/23-remote-browser-isolation.md': '0588d0e2f42be8b4f1b08619fb1fa0768ff2cf2d2ab07eadc1248e9858ab9b37', '/home/notroot/research/competetive/_issues/skid/01-scaffold-ci-release.md': '79f45ffa81a7f9e8ddcd2acd206b515bdd935e65776e742837c242132cb97367', '/home/notroot/research/competetive/_issues/skid/02-smartid-device-link-spike.md': '85d6b62e5c97e300724e2d95ea96b75d3cce19dc0ddf3f01fdf299a16c4b4d2e', '/home/notroot/research/competetive/_issues/skid/03-smartid-rp-v3-client.md': '4b2ff6c763b2375d9b5b99798283ce134d797621c8fc48b76dfb7684732191fc', '/home/notroot/research/competetive/_issues/skid/04-smartid-notification-flow.md': '7871e1028a94055069e0747773c60f468001fe2f41fc0ae373d5f923d4e8648b', '/home/notroot/research/competetive/_issues/skid/05-authenticator-interface.md': '2c094b5b755f52c3cf8b2d0af48c97e9613a4fe91a3c5072a48a85e027135220', '/home/notroot/research/competetive/_issues/skid/06-oidc-provider.md': 'b5a0e0f7f251d3070f4c20115d9a8844f6470addf93dc2d0df0e76fdc56e62c7', '/home/notroot/research/competetive/_issues/skid/07-binary-login-page-config.md': 'baa3543ae17356e4330f847c538989095a07d330ac42150e3f5bfe933dae8042', '/home/notroot/research/competetive/_issues/skid/08-tls-pinning-trust-anchors.md': 'bf4d7c7638a25b473742cb6765d8d8f320b06f47ae712c4bd385f6f340215319', '/home/notroot/research/competetive/_issues/skid/09-pii-log-redaction.md': 'dd25b75530755a847a36d04f924f938b883a0c8eceef40ee891e7430f8d6303d', '/home/notroot/research/competetive/_issues/skid/10-no-telemetry-zero-retention.md': '1fcc3ba60dfc65a6757ca969096bc63ff4ec8d9cf75a94a5446c248f3b965735', '/home/notroot/research/competetive/_issues/skid/11-demo-env-guard.md': 'fd32fa826175037dd0dc2b517176df52a125e420f6c16a776bc0af2b2be238e4', '/home/notroot/research/competetive/_issues/skid/12-legal-notices-clean-room.md': '6a2511bca298d2c0e63d099c63c588f6462e313631cca1c8d22ca3840a08a03b', '/home/notroot/research/competetive/_issues/skid/13-data-flow-doc.md': '6fc70a5b74bf8b4784ef2853790c48903af8b492f3b541bd09652e3704ed261f', '/home/notroot/research/competetive/_issues/skid/14-compose-quickstart.md': '93750fae1249ff210cfca0de976645fe5e56dace4c4d3545970fa5bcd096a188', '/home/notroot/research/competetive/_issues/skid/15-idp-integration-kits.md': 'd6300070fcfb88edaca25d7ede1a8e8bc6c16b2284d0f694549b79540115e773', '/home/notroot/research/competetive/_issues/skid/16-login-page-i18n.md': '06e2fc51f69af41a877b45be77b349ae27f26eebee1b04fecb4ea8da03d84327', '/home/notroot/research/competetive/_issues/skid/17-protocol-change-tracking.md': 'fbaf7cccf4381bcc98532214d9d2d07c97971aa5a2e65e7f17287cfc8bcb50eb', '/home/notroot/research/competetive/_issues/skid/18-framework-oidc-examples.md': 'aa220c187da3ca19bc51b86e6bca77e71b704984691e95b8f0aa6e6890055dab', '/home/notroot/research/competetive/_issues/skid/19-mobile-id.md': '8497cf79866392ff66d0766b8e1df23a8d099944ac7e0f851e4ee7eb82f8a0f3', '/home/notroot/research/competetive/_issues/skid/20-method-chooser.md': '590b53c55ecc20c623cecccaa86937601a91db496d49df6eb5a71e7230f88286', '/home/notroot/research/competetive/_issues/skid/21-web-eid-idcard.md': 'c9bf760ddb1f04481a822ddf6a60201de0f1f71773dd2899dab5873784e25c91', '/home/notroot/research/competetive/_issues/skid/22-eudi-wallet-oid4vp.md': 'de55e5f0bf161c7384817a6b293903057ee81f94734228ccd201f990bc0455c3', '/home/notroot/research/competetive/_issues/skid/23-eudi-conformance-harness.md': '0b62a3a0b5cb0d65e0a65ec38cfd3aea29d00114aaf87d0d318ad45d87d1470c', '/home/notroot/research/competetive/_issues/skid/24-keycloak-spi.md': 'eebd68ecbf9c021dc6335aa948510912b2837d0b05bc46023a4f3bf20866a285', '/home/notroot/research/competetive/_issues/skid/25-python-rp-client.md': 'd8ec5ca4d8f1ca924e1aa2902e899f897f88ecd3d3c5584ab26e6c3190a5a318', '/home/notroot/research/competetive/_issues/skid/26-doctor-health-check.md': 'f73324d7817146fa8b32beea97ad8bc4fc09a5104987a81dd78c6763a7cfc696', '/home/notroot/research/competetive/_issues/skid/27-mock-rp-api-server.md': 'a4ef39ee035d3ce5163152d2bb5031dd2f461ab26fc82fa8e2749015ed28310e', '/home/notroot/research/competetive/_issues/skid/28-signing-sessions.md': '6eb2a5753843a3ab217c9869d067782805dde3891990e5c0c98397ae19267217', '/home/notroot/research/competetive/_issues/skid/29-legacy-rp-api.md': '8b956b9dc62f64d98fe511f4ec85fe55472d8491cdd2863e9846bf0ea1afcf52', '/home/notroot/research/competetive/_issues/skid/30-wordpress-plugin.md': '8d66d44477051858fffa8a02be34013150aa940f6a999756ddde843b910abf06', '/home/notroot/research/competetive/eideasy.com/RECOMMENDATION.md': '806ec4ae6ff9fad3597af4fdc0f9b639df9908e1138bac7081b049e9fadbd695', '/home/notroot/research/competetive/eideasy.com/forecasts.csv': 'b7251f846a29f52944b015368e4bf70227732e096cca4a725102bf2e691d3bbb', '/home/notroot/research/competetive/eideasy.com/legal/contributions-checklist.md': '949ea974b9ff08b61e0fb1be5bce1444c8cbd03982631647e2177fed4dab9de1', '/home/notroot/research/competetive/eideasy.com/prompt.md': '6a4595ce9b08580cf6e0bcb42c8b2ceea545011c1c33e087e8144624bb7993bd', '/home/notroot/research/competetive/eideasy.com/signals.csv': '81090cdeafabff5ed551f4d04a4fd35054e0be2b5ba7cd09af949ea5f38c1715', '/home/notroot/research/competetive/eideasy.com/watch_log.csv': 'a1da00a68214622ced879702d3311dc299a0d57f65479a61c0aab63cdb35d5ff', '/home/notroot/research/competetive/glazer.ee/candidates.csv': '3690dea2b1b4e8d085162594a6151d01b93b5feaf1ab0d99575b578f83715d1c', '/home/notroot/research/competetive/glazer.ee/deliverable/compliance.md': 'f9ff0571a61aabc375aebca50742218aebfcdd8f180cde499483412366fdf03b', '/home/notroot/research/competetive/glazer.ee/deliverable/plan-30d.md': '496e4206356be8bd485921aaaee712c52e2269733799d224cc00d3c989c09982', '/home/notroot/research/competetive/glazer.ee/deliverable/recommendation.md': 'be23fe9796201a8f52aa704640f9bb77461140c27a61c6c35265458840575c35', '/home/notroot/research/competetive/glazer.ee/forecasts.csv': '16467710c113235ef71e6da0c1098f5799242509bc4086c16abcb361c243935a', '/home/notroot/research/competetive/glazer.ee/prompt.md': '9da60a41e694d2992fd0e7e90fd12be2bb5c854ccca83c9118e4b65b9316310b', '/home/notroot/research/competetive/glazer.ee/signals.csv': '1ff7cd2e58f2bfeb58f344555efa2716097d731b0e284b5a467fe013d33c1bce', '/home/notroot/research/competetive/rankings/RANKING.md': 'e6d39049a211561c3a2bb3056312b5dcda8d69c7ada2b82aa30f13dfd751ca07', '/home/notroot/research/competetive/rankings/capabilities.csv': '42907c1059270dcf0d97878bebfe74b44160601d63033ffd7333631826b334d0', '/home/notroot/research/competetive/rankings/forecasts.csv': 'c3478f31e337e520dc4aabbc3d50272dce7f48ad98599d80e8f24e0f13a460e7', '/home/notroot/research/competetive/rankings/inventory.csv': 'e87fab9557c31bbad0b024305643325992ad841052e84b1745511f9e3d453296', '/home/notroot/research/competetive/skidsolutions.eu/analysis_phase3.md': 'c78cc86a60e3ebdd5b214401da60084f6e1440417349735f77a388f3b84f1c82', '/home/notroot/research/competetive/skidsolutions.eu/artefacts_b.md': '44dcf132bf16ebb6c597bcc3fca04c2587a5c573535d4218f6a0548b8f3b892b', '/home/notroot/research/competetive/skidsolutions.eu/compliance.md': '9dc753557c676eda93158a103d3516ca691a7b51d47c00491cc863bb7e1240aa', '/home/notroot/research/competetive/skidsolutions.eu/demand.md': 'e599effccb805a5df034b52f045af42bf6da179cd3324b0c9414dd17f383c9a6', '/home/notroot/research/competetive/skidsolutions.eu/distribution.md': '9f52b37f3e406441efe0659ecc5c401c8621561dd8e215cb582eb390fa896d0a', '/home/notroot/research/competetive/skidsolutions.eu/forecasts.csv': '82e2c3b78d7f49f4466bc285b192bcf6f71ab858b56dd8cc792038a8553e8ed5', '/home/notroot/research/competetive/skidsolutions.eu/notes_a.md': 'ab0bac5c8fc7e4d408c9bc3d8d1688047d96110499fe08de191f30ad1ee38c20', '/home/notroot/research/competetive/skidsolutions.eu/notes_b.md': '2bfa65314c5e8a235c180cf3ca9e05116b32f3ff404a5192b624b47360650aa7', '/home/notroot/research/competetive/skidsolutions.eu/notes_c.md': '9fcf8adbce12f710fe6f5e12539e607f2a042f1093067c28f359a1e593ea27d3', '/home/notroot/research/competetive/skidsolutions.eu/opportunities.csv': 'b8686783699a00ce23c9fcf05f4f5fb74c41afa06eae1f41d8b2703f16416c76', '/home/notroot/research/competetive/skidsolutions.eu/oss_inventory.md': 'bccf6d6342941fee4f3e967f78f2cbdb31f71f4d8702a04bddca45e86659f1ed', '/home/notroot/research/competetive/skidsolutions.eu/plan_30d.md': 'c9aeb18d81154354d323301aa3111dbcc42d95e03ae965269e58b871a20ccb40', '/home/notroot/research/competetive/skidsolutions.eu/procurement.md': 'a68851fd9baa9b347b66daf8ec41b895663df44b4b075f49aed2a68e67bae56e', '/home/notroot/research/competetive/skidsolutions.eu/prompt.md': '2908eb4cd04f33f7d9b5674a27c7e41255b2b2f9cf08ea39fb8548ec44f645b0', '/home/notroot/research/competetive/skidsolutions.eu/proposal.md': 'f7032a8de98e30f86f24c1a57fa34ff80c6551392f6e023a1c98f58eb464796a', '/home/notroot/research/competetive/skidsolutions.eu/signals.csv': '732a7d545eb746cbda899124b6089e670e886ba2986aa1de62f87084c515cd01', '/home/notroot/research/competetive/skidsolutions.eu/signals_a.csv': '4085441066fb6a154c534bae1b73a76ead3b0b41cd462583a7a7ef887aa0da15', '/home/notroot/research/competetive/skidsolutions.eu/signals_b.csv': 'df9a80de03bcd410c722d2a6374dd375c4b92d5dae34c7432f405c280ac7fa2b', '/home/notroot/research/competetive/skidsolutions.eu/signals_c.csv': 'aa32ef6453a140573a4b406465e9bd9ba0bf48bc3abf9f1be008995efb318aa2', '/home/notroot/research/competetive/skidsolutions.eu/signals_section.md': '297aa2e563665f9f8493dea676005eb3a6660930258d67f1da4b538cf44123c0'}
REQUIRED_DOCS = ['README.md','product-brief-eidbridge-2026-11-18.md','prd.md','addendum.md','architecture.md','ux-design-specification.md','epics.md','roadmap.md','source-reconciliation.md','implementation-readiness-report-2026-11-18.md']
REQUIRED_RESEARCH = ['skidsolutions.eu/proposal.md','skidsolutions.eu/plan_30d.md','skidsolutions.eu/compliance.md','skidsolutions.eu/distribution.md','skidsolutions.eu/demand.md','skidsolutions.eu/procurement.md','skidsolutions.eu/oss_inventory.md','skidsolutions.eu/analysis_phase3.md','eideasy.com/RECOMMENDATION.md','eideasy.com/legal/contributions-checklist.md','rankings/RANKING.md','glazer.ee/deliverable/recommendation.md','glazer.ee/deliverable/plan-30d.md','glazer.ee/deliverable/compliance.md']

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--root',default='/home/notroot/Documents/eidbridge')
    ap.add_argument('--research',default='/home/notroot/research/competetive')
    args=ap.parse_args()
    root=Path(args.root).resolve(); research=Path(args.research).resolve()
    plan=root/'_bmad-output/planning-artifacts'
    failures=[]; counts={}
    def check(ok,code,detail):
        if not ok: failures.append({'code':code,'detail':str(detail)})
        return bool(ok)
    def read(p):
        try: return p.read_text()
        except (OSError,UnicodeError) as e:
            check(False,'READ',f'{p}: {e}');return ''
    def js(p):
        try: return json.loads(read(p))
        except (ValueError,TypeError) as e:
            check(False,'JSON',f'{p}: {e}');return {}
    def csvrows(p):
        return list(csv.DictReader(read(p).splitlines()))
    def artifact(v):
        target=str(v).split('#')[0]
        p=Path(target)
        if not p.is_absolute(): p=plan/p
        return p
    def exact_ids(rows,expected,label):
        ids=[str(x.get('id','')) for x in rows]
        check(len(ids)==len(set(ids)),label+'_DUPLICATE',ids)
        check(set(ids)==set(expected),label+'_COVERAGE',{'missing':sorted(set(expected)-set(ids)),'extra':sorted(set(ids)-set(expected))})
        counts[label.lower()]=len(ids)
    expected_files=[plan/p for p in REQUIRED_DOCS]+[plan/'research/source-manifest.json',plan/'research/traceability.json',plan/'research/competitive-watch.csv',root/'_bmad-output/implementation-artifacts/sprint-status.yaml',root/'docs/project-overview.md',root/'_bmad-output/project-context.md',root/'tools/verify_bmad_artifacts.py']
    for p in expected_files: check(p.is_file(),'MISSING_ARTIFACT',p)
    # These immutable expectations were captured before candidate authoring.
    for path,digest in FROZEN_HASHES.items():
        p=Path(path)
        check(p.is_file() and hashlib.sha256(p.read_bytes()).hexdigest()==digest,'FROZEN_SOURCE_CHANGED',p)
    copy=root/'tools/verify_bmad_artifacts.py'
    if copy.is_file():check(copy.read_bytes()==Path(__file__).read_bytes(),'VERIFIER_CHANGED',copy)
    snap=js(plan/'research/github-issues-2026-11-18.json')
    source_issues=snap.get('issues',[])
    check(snap.get('complete') is True,'ISSUE_SNAPSHOT_INCOMPLETE','Snapshot must state retrieval is complete')
    trace=js(plan/'research/traceability.json')
    issues=trace.get('issues',[])
    expected_numbers={x.get('number') for x in source_issues}; numbers=[x.get('number') for x in issues]
    check(set(numbers)==expected_numbers and len(numbers)==len(expected_numbers),'ISSUE_COVERAGE',{'expected':sorted(expected_numbers),'actual':numbers})
    counts['issues']=len(issues)
    original_by_number={x['number']:x for x in source_issues}
    prd=read(plan/'prd.md'); epics=read(plan/'epics.md')
    stories=re.findall(r'^### Story ([0-9]+\.[0-9]+):',epics,re.M)
    check(len(stories)==len(set(stories)),'DUPLICATE_STORY_HEADING',stories)
    order={s:i for i,s in enumerate(stories)}
    seen_story=set(); graph={}
    for row in issues:
        n=row.get('number'); original=original_by_number.get(n)
        if original is None:continue
        body=original.get('body') or ''; story=str(row.get('story_id','')); req=str(row.get('requirement_id',''))
        expected_req=f'FR-{n:03d}'
        check(req==expected_req,'REQUIREMENT_ID',f'Issue {n}: {req} != {expected_req}')
        check(expected_req in prd and expected_req in epics,'REQUIREMENT_COVERAGE',expected_req)
        check(bool(re.fullmatch(r'[0-9]+\.[0-9]+',story)),'STORY_ID',story)
        check(story not in seen_story,'ISSUE_STORY_DUPLICATE',story);seen_story.add(story)
        check(story in order,'STORY_MISSING',story)
        check(bool(row.get('epic_id')),'EPIC_MISSING',n)
        check(str(row.get('status','')).lower() not in {'done','complete','completed','implemented','shipped','closed'},'FALSE_IMPLEMENTED_STATE',n)
        check(hashlib.sha256(body.encode()).hexdigest()==row.get('original_body_sha256'),'ISSUE_BODY_HASH',n)
        ac=re.findall(r'^\s*- \[ \] (.+)$',body,re.M)
        check(row.get('acceptance_criteria')==ac,'ISSUE_AC_PRESERVATION',n)
        for text in ac:check(text in epics,'EPICS_AC_MISSING',f'#{n}: {text}')
        notes=body.split('## Notes',1)[1].strip() if '## Notes' in body else ''
        check(str(row.get('original_notes','')).strip()==notes,'ISSUE_NOTES_PRESERVATION',n)
        spec=str(row.get('source_spec',''));p=Path(spec)
        if not p.is_absolute():p=research/p
        check(p.is_file(),'ISSUE_SPEC_MISSING',f'{n}: {p}')
        deps=[str(d) for d in row.get('depends_on',[])]
        graph[story]=deps
        for dep in deps:
            check(dep in order,'DEPENDENCY_MISSING',f'{story}->{dep}')
            if story in order and dep in order:check(order[dep]<order[story],'FORWARD_DEPENDENCY',f'{story}->{dep}')
    active=set();done=set()
    def visit(node):
        if node in active:check(False,'DEPENDENCY_CYCLE',node);return
        if node in done:return
        active.add(node)
        for dep in graph.get(node,[]):visit(dep)
        active.remove(node);done.add(node)
    for node in graph:visit(node)
    opps=csvrows(research/'skidsolutions.eu/opportunities.csv')
    caps=csvrows(research/'rankings/capabilities.csv')
    inv=csvrows(research/'rankings/inventory.csv')
    sig=csvrows(research/'skidsolutions.eu/signals.csv')
    forecasts=csvrows(research/'skidsolutions.eu/forecasts.csv')
    exact_ids(trace.get('opportunities',[]),[x['opportunity_id'] for x in opps],'OPPORTUNITIES')
    exact_ids(trace.get('capabilities',[]),[x['capability_id'] for x in caps if x['target']=='skidsolutions.eu'],'CAPABILITIES')
    exact_ids(trace.get('milestones',[]),[x['item_id'] for x in inv if x['source_corpus']=='skid' and x['kind']=='milestone'],'MILESTONES')
    exact_ids(trace.get('signals',[]),[x['signal_id'] for x in sig],'SIGNALS')
    exact_ids(trace.get('forecasts',[]),[x['forecast_id'] for x in forecasts],'FORECASTS')
    research_items=trace.get('research_items',[])
    ids=[x.get('id') for x in research_items]
    check(len(ids)==len(set(ids)),'RESEARCH_ITEM_DUPLICATE',ids)
    for name in REQUIRED_RESEARCH:
        check(any(str(x.get('source','')).endswith(name) for x in research_items),'RESEARCH_SOURCE_UNMAPPED',name)
    for key in ['opportunities','capabilities','milestones','research_items','signals','forecasts']:
        for x in trace.get(key,[]):
            check(bool(x.get('disposition')),'DISPOSITION_MISSING',f'{key}: {x.get("id")}')
            check(bool(x.get('artifact')) and artifact(x.get('artifact','')).is_file(),'DESTINATION_MISSING',f'{key}: {x.get("id")} -> {x.get("artifact")}')
            if key not in {'signals','forecasts'}:check(bool(x.get('rationale')),'RATIONALE_MISSING',f'{key}: {x.get("id")}')
            if key=='research_items':check(bool(x.get('locator')),'LOCATOR_MISSING',x.get('id'))
    counts['research_items']=len(research_items)
    watch=csvrows(plan/'research/competitive-watch.csv')
    byforecast={x.get('forecast_id'):x for x in watch}
    check(len(watch)==len(forecasts) and set(byforecast)=={x['forecast_id'] for x in forecasts},'WATCH_COVERAGE',list(byforecast))
    for original in forecasts:
        row=byforecast.get(original['forecast_id'],{})
        for k,v in original.items():check(row.get(k)==v,'WATCH_SOURCE_DRIFT',f'{original["forecast_id"]}.{k}')
    manifest=js(plan/'research/source-manifest.json');files=manifest.get('files',[])
    seen=set()
    for row in files:
        p=Path(str(row.get('path','')))
        if not p.is_absolute():p=research/p
        check(str(p) not in seen,'MANIFEST_DUPLICATE',p);seen.add(str(p))
        check(p.is_file(),'MANIFEST_SOURCE_MISSING',p)
        if p.is_file():check(hashlib.sha256(p.read_bytes()).hexdigest()==row.get('sha256'),'MANIFEST_HASH',p)
        check(bool(row.get('role')) and bool(row.get('disposition')),'MANIFEST_CLASSIFICATION',p)
    for path in REQUIRED_RESEARCH+['skidsolutions.eu/opportunities.csv','skidsolutions.eu/signals.csv','skidsolutions.eu/forecasts.csv','rankings/inventory.csv','rankings/capabilities.csv']:
        check(str(research/path) in seen,'MANIFEST_SOURCE_OMITTED',path)
    counts['manifest_sources']=len(files)
    authored=[plan/x for x in REQUIRED_DOCS]+[root/'docs/project-overview.md',root/'_bmad-output/project-context.md']
    for p in authored:
        content=read(p)
        check(not re.search(r'\{\{[^}]+\}\}|TEMPLATE_[A-Z_]+',content),'TEMPLATE_PLACEHOLDER',p)
        # Fenced command examples are not author links; inline code is not links.
        content=re.sub(r'^```.*?^```','',content,flags=re.M|re.S)
        content=re.sub(r'`[^`]*`','',content)
        for link in re.findall(r'!?\[[^\]]*\]\(([^)]+)\)',content):
            link=link.split(' ',1)[0].strip('<>')
            if not link or link.startswith(('#','http:','https:','mailto:','plugin:','app:')):continue
            target=unquote(link.split('#',1)[0]);target=re.sub(r':\d+$','',target)
            q=Path(target)
            if not q.is_absolute():q=p.parent/q
            check(q.exists(),'BROKEN_LOCAL_LINK',f'{p}: {link}')
    counts['story_headings']=len(stories)
    report={'verifier':'eidbridge-bmad-coverage-2026-11-18','verifier_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'verdict':'FAIL' if failures else 'PASS','scope':'PROXY ONLY: structural/source preservation, not semantic or implementation proof','counts':counts,'failures':failures}
    print(json.dumps(report,indent=2,ensure_ascii=False))
    return 1 if failures else 0

if __name__=='__main__':sys.exit(main())
