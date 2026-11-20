// SPDX-License-Identifier: MIT OR Apache-2.0
package ee.eidbridge.example;

import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.policy.jaxb.CertificateConstraints;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Example integrator for the eidbridge signing API (digest relay).
 *
 * <pre>
 *   sign     --bridge URL --client-id ID --signer PNOEE-... --ca ca.pem --in FILE --out FILE.asice
 *   validate --in FILE.asice --root root.pem
 * </pre>
 *
 * The client secret is read from EIDBRIDGE_CLIENT_SECRET. DSS is used only as a
 * Maven dependency (LGPL-2.1); no DSS code is copied here.
 *
 * The JSON handling is deliberately minimal (flat string fields) to avoid another dependency.
 */
public final class Main {

    private static final HttpClient HTTP = HttpClient.newHttpClient();

    public static void main(String[] argv) throws Exception {
        if (argv.length == 0) {
            usage();
            return;
        }
        Map<String, String> a = parse(argv);
        switch (argv[0]) {
            case "sign" -> sign(a);
            case "validate" -> System.exit(validate(a));
            default -> usage();
        }
    }

    private static void usage() {
        System.err.println("usage: sign --bridge URL --client-id ID --signer PNOEE-... --ca ca.pem --in FILE --out FILE.asice\n"
                + "       validate --in FILE.asice --root root.pem [--no-revocation true]\n"
                + "       (client secret in EIDBRIDGE_CLIENT_SECRET)");
        System.exit(2);
    }

    private static Map<String, String> parse(String[] argv) {
        Map<String, String> m = new java.util.HashMap<>();
        for (int i = 1; i + 1 < argv.length; i += 2) {
            m.put(argv[i].replaceFirst("^--", ""), argv[i + 1]);
        }
        return m;
    }

    private static String need(Map<String, String> a, String k) {
        String v = a.get(k);
        if (v == null) {
            throw new IllegalArgumentException("missing --" + k);
        }
        return v;
    }

    // ---- sign ----------------------------------------------------------------

    private static void sign(Map<String, String> a) throws Exception {
        String bridge = need(a, "bridge").replaceAll("/+$", "");
        String clientId = need(a, "client-id");
        String secret = System.getenv("EIDBRIDGE_CLIENT_SECRET");
        if (secret == null || secret.isEmpty()) {
            throw new IllegalStateException("set EIDBRIDGE_CLIENT_SECRET");
        }
        String auth = "Basic " + Base64.getEncoder()
                .encodeToString((clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
        Bridge br = new Bridge(bridge, auth);

        // Step 1: signing certificate.
        String certJob = br.post("/api/v1/sign/certificate", "{\"signer\":" + q(need(a, "signer")) + "}");
        Map<String, String> cert = br.await(str(certJob, "id"));
        CertificateToken leaf = DSSUtils.loadCertificate(Base64.getDecoder().decode(cert.get("certificate")));
        System.err.println("certificate level: " + cert.get("certificate_level") + ", subject: "
                + leaf.getSubject().getRFC2253());

        // Chain: leaf + the issuing certificate found in the --ca bundle.
        List<CertificateToken> chain = new ArrayList<>();
        chain.add(leaf);
        for (CertificateToken c : loadPem(need(a, "ca"))) {
            if (!c.isSelfSigned() && leaf.isSignedBy(c)) {
                chain.add(c);
            }
        }
        if (chain.size() < 2) {
            throw new IllegalStateException("no issuer of the signing certificate in " + a.get("ca"));
        }

        // Build the ASiC-E / XAdES-BASELINE-B parameters with external signing.
        DSSDocument doc = new FileDocument(need(a, "in"));
        ASiCWithXAdESSignatureParameters p = new ASiCWithXAdESSignatureParameters();
        p.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        p.aSiC().setContainerType(ASiCContainerType.ASiC_E);
        p.setDigestAlgorithm(DigestAlgorithm.SHA256);
        // Order matters: setSigningCertificate derives the encryption algorithm from the key (RSA),
        // so RSASSA-PSS must be set after it. With SHA-256 this yields RSA_SSA_PSS_SHA256_MGF1.
        p.setSigningCertificate(leaf);
        p.setCertificateChain(chain);
        p.setEncryptionAlgorithm(EncryptionAlgorithm.RSASSA_PSS);

        // Offline verifier: no AIA, OCSP or CRL sources, so DSS never fetches anything.
        ASiCWithXAdESService service = new ASiCWithXAdESService(new CommonCertificateVerifier());

        ToBeSigned tbs = service.getDataToSign(doc, p);
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(tbs.getBytes());

        // Step 2: the bridge relays the digest to the signer's phone.
        String body = "{\"certificate\":" + q(str(certJob, "id"))
                + ",\"digest\":" + q(Base64.getEncoder().encodeToString(digest))
                + ",\"hash_algorithm\":\"SHA-256\",\"signature_algorithm\":\"rsassa-pss\""
                + ",\"display_text\":" + q("Sign " + new java.io.File(need(a, "in")).getName()) + "}";
        String signJob = br.post("/api/v1/sign", body);
        System.err.println("VERIFICATION CODE (must match the phone): " + str(signJob, "verification_code"));
        Map<String, String> res = br.await(str(signJob, "id"));

        byte[] sig = Base64.getDecoder().decode(res.get("signature"));
        SignatureValue sv = new SignatureValue(SignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1, sig);
        DSSDocument signed = service.signDocument(doc, p, sv);
        signed.save(need(a, "out"));
        System.err.println("wrote " + a.get("out"));
    }

    // ---- validate --------------------------------------------------------------

    /** Returns 0 when every signature is TOTAL_PASSED, 1 otherwise. */
    private static int validate(Map<String, String> a) throws Exception {
        CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
        for (CertificateToken c : loadPem(need(a, "root"))) {
            if (c.isSelfSigned()) {
                trusted.addCertificate(c);
            }
        }
        CommonCertificateVerifier cv = new CommonCertificateVerifier();
        cv.setTrustedCertSources(trusted);

        DocumentValidator v = SignedDocumentValidator.fromDocument(new FileDocument(need(a, "in")));
        v.setCertificateVerifier(cv);
        // The mock upstream publishes no OCSP/CRL, so with DSS's default policy every signature is
        // INDETERMINATE for lack of revocation data. --no-revocation loads the same default policy
        // from the DSS jar and sets only the revocation-availability checks to IGNORE.
        Reports reports = "true".equals(a.get("no-revocation")) ? v.validateDocument(noRevocationPolicy()) : v.validateDocument();
        SimpleReport sr = reports.getSimpleReport();
        if (sr.getSignatureIdList().isEmpty()) {
            System.out.println("no signatures found");
            return 1;
        }
        int rc = 0;
        for (String id : sr.getSignatureIdList()) {
            String ind = String.valueOf(sr.getIndication(id));
            System.out.println("signature " + id + ": indication=" + ind + " subIndication=" + sr.getSubIndication(id)
                    + " format=" + sr.getSignatureFormat(id));
            sr.getAdESValidationErrors(id).forEach(m -> System.out.println("  error: " + m.getValue()));
            sr.getAdESValidationWarnings(id).forEach(m -> System.out.println("  warning: " + m.getValue()));
            if (!"TOTAL_PASSED".equals(ind)) {
                rc = 1;
            }
        }
        return rc;
    }

    private static ValidationPolicy noRevocationPolicy() throws Exception {
        try (InputStream in = ValidationPolicyFacade.class.getResourceAsStream("/policy/constraint.xml")) {
            ConstraintsParameters cp = ValidationPolicyFacade.newFacade().unmarshall(in);
            for (CertificateConstraints c : new CertificateConstraints[] {
                    cp.getSignatureConstraints().getBasicSignatureConstraints().getSigningCertificate(),
                    cp.getSignatureConstraints().getBasicSignatureConstraints().getCACertificate()}) {
                c.setRevocationDataAvailable(ignore());
                c.setAcceptableRevocationDataFound(ignore());
            }
            return new EtsiValidationPolicy(cp);
        }
    }

    private static LevelConstraint ignore() {
        LevelConstraint l = new LevelConstraint();
        l.setLevel(Level.IGNORE);
        return l;
    }

    // ---- helpers ---------------------------------------------------------------

    private static List<CertificateToken> loadPem(String path) throws Exception {
        List<CertificateToken> out = new ArrayList<>();
        try (InputStream in = new FileInputStream(path)) {
            for (java.security.cert.Certificate c : java.security.cert.CertificateFactory.getInstance("X.509")
                    .generateCertificates(in)) {
                out.add(new CertificateToken((java.security.cert.X509Certificate) c));
            }
        }
        return out;
    }

    private static String q(String s) {
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private static String str(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"").matcher(json);
        return m.find() ? m.group(1) : null;
    }

    /** Minimal client for the bridge signing API. */
    private static final class Bridge {
        private final String base;
        private final String auth;

        Bridge(String base, String auth) {
            this.base = base;
            this.auth = auth;
        }

        String post(String path, String json) throws Exception {
            HttpRequest r = HttpRequest.newBuilder(URI.create(base + path))
                    .header("Authorization", auth).header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json)).build();
            HttpResponse<String> resp = HTTP.send(r, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 202) {
                throw new IllegalStateException("POST " + path + " -> " + resp.statusCode() + " " + resp.body());
            }
            return resp.body();
        }

        /** Polls until the job is no longer pending; the signature is delivered only once. */
        Map<String, String> await(String id) throws Exception {
            for (int i = 0; i < 600; i++) {
                HttpRequest r = HttpRequest.newBuilder(URI.create(base + "/api/v1/sign/" + id))
                        .header("Authorization", auth).GET().build();
                HttpResponse<String> resp = HTTP.send(r, HttpResponse.BodyHandlers.ofString());
                if (resp.statusCode() != 200) {
                    throw new IllegalStateException("GET job -> " + resp.statusCode() + " " + resp.body());
                }
                String status = str(resp.body(), "status");
                if ("complete".equals(status)) {
                    Map<String, String> m = new java.util.HashMap<>();
                    for (String k : new String[] {"certificate", "certificate_level", "signature"}) {
                        m.put(k, str(resp.body(), k));
                    }
                    return m;
                }
                if ("failed".equals(status)) {
                    throw new IllegalStateException("job failed: " + str(resp.body(), "error"));
                }
                Thread.sleep(500);
            }
            throw new IllegalStateException("timed out waiting for job");
        }
    }
}
