package com.ccn.pki.controller;

import com.ccn.pki.dto.*;
import com.ccn.pki.model.CaEntity;
import com.ccn.pki.model.CertificateEntity;
import com.ccn.pki.model.CertificateStatus;
import com.ccn.pki.model.CrlEntity;
import com.ccn.pki.repository.CertificateRepository;
import com.ccn.pki.repository.CrlRepository;
import com.ccn.pki.service.CaService;
import com.ccn.pki.service.CertificateIssuingService;
import com.ccn.pki.service.CrlService;
import com.ccn.pki.service.OpenSslVerificationService;
import com.ccn.pki.service.ValidationService;
import com.ccn.pki.util.PemUtils;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * ===================================================================
 * Contrôleur REST API : Points de terminaison pour l'automatisation PKI
 * ===================================================================
 */
@RestController
@RequestMapping("/api/pki")
public class PkiRestController {

    private final CaService caService;
    private final CertificateIssuingService certificateIssuingService;
    private final CrlService crlService;
    private final ValidationService validationService;
    private final OpenSslVerificationService openSslVerificationService;
    private final CertificateRepository certificateRepository;
    private final CrlRepository crlRepository;

    public PkiRestController(CaService caService,
                             CertificateIssuingService certificateIssuingService,
                             CrlService crlService,
                             ValidationService validationService,
                             OpenSslVerificationService openSslVerificationService,
                             CertificateRepository certificateRepository,
                             CrlRepository crlRepository) {
        this.caService = caService;
        this.certificateIssuingService = certificateIssuingService;
        this.crlService = crlService;
        this.validationService = validationService;
        this.openSslVerificationService = openSslVerificationService;
        this.certificateRepository = certificateRepository;
        this.crlRepository = crlRepository;
    }

    /**
     * Métriques et état général de la PKI
     */
    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> getPkiStatus() {
        Map<String, Object> status = new HashMap<>();
        status.put("caInitialized", caService.isCaInitialized());
        if (caService.isCaInitialized()) {
            CaEntity ca = caService.getActiveCa();
            status.put("caSubject", ca.getSubjectDn());
            status.put("caSerialNumber", ca.getSerialNumber());
            status.put("caExpiresAt", ca.getNotAfter());
            status.put("caSha256Fingerprint", ca.getSha256Fingerprint());
        }
        status.put("totalCertificates", certificateRepository.count());
        status.put("activeCertificates", certificateRepository.countByStatus(CertificateStatus.ACTIVE));
        status.put("revokedCertificates", certificateRepository.countByStatus(CertificateStatus.REVOKED));
        status.put("expiredCertificates", certificateRepository.countByStatus(CertificateStatus.EXPIRED));

        crlRepository.findFirstByOrderByCrlNumberDesc().ifPresent(crl -> {
            status.put("crlNumber", crl.getCrlNumber());
            status.put("crlNextUpdate", crl.getNextUpdate());
            status.put("crlRevokedCount", crl.getRevokedCount());
        });

        return ResponseEntity.ok(status);
    }

    /**
     * Initialisation / Réinitialisation de la Root CA
     */
    @PostMapping("/ca/init")
    public ResponseEntity<?> initRootCa(@RequestParam(defaultValue = "CN=CCN Root CA, OU=Laboratoire Sécurité, O=ENSET Mohammedia, C=MA") String subjectDn,
                                        @RequestParam(defaultValue = "10") int validityYears,
                                        @RequestParam(defaultValue = "4096") int keySize) {
        try {
            CaEntity ca = caService.initializeRootCa(subjectDn, validityYears, keySize);
            crlService.generateAndPublishCrl();
            return ResponseEntity.ok(ca);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Téléchargement du certificat de la Root CA (format PEM ou DER)
     */
    @GetMapping("/ca/cert")
    public ResponseEntity<byte[]> downloadCaCert(@RequestParam(defaultValue = "pem") String format) {
        try {
            X509Certificate caCert = caService.getCaCertificate();
            if (caCert == null) {
                return ResponseEntity.notFound().build();
            }

            if ("der".equalsIgnoreCase(format)) {
                byte[] der = caCert.getEncoded();
                return ResponseEntity.ok()
                        .contentType(MediaType.parseMediaType("application/x-x509-ca-cert"))
                        .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"rootCA.crt\"")
                        .body(der);
            } else {
                byte[] pemBytes = PemUtils.toPem(caCert).getBytes(StandardCharsets.UTF_8);
                return ResponseEntity.ok()
                        .contentType(MediaType.parseMediaType("application/x-pem-file"))
                        .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"rootCA.pem\"")
                        .body(pemBytes);
            }
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * Émission d'un certificat avec génération automatique de clé privée
     */
    @PostMapping("/certificates/issue")
    public ResponseEntity<?> issueCertificate(@Valid @RequestBody IssueCertificateRequest request) {
        try {
            CertificateEntity cert = certificateIssuingService.issueCertificate(request);
            return ResponseEntity.ok(cert);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Émission d'un certificat à partir d'une CSR PKCS#10
     */
    @PostMapping("/certificates/issue-csr")
    public ResponseEntity<?> issueCertificateFromCsr(@Valid @RequestBody IssueCsrRequest request) {
        try {
            CertificateEntity cert = certificateIssuingService.issueCertificateFromCsr(request);
            return ResponseEntity.ok(cert);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Liste des certificats émis
     */
    @GetMapping("/certificates")
    public ResponseEntity<List<CertificateEntity>> getAllCertificates() {
        return ResponseEntity.ok(certificateRepository.findAllByOrderByIssuedAtDesc());
    }

    /**
     * Détails d'un certificat par numéro de série
     */
    @GetMapping("/certificates/{serial}")
    public ResponseEntity<?> getCertificate(@PathVariable String serial) {
        return certificateRepository.findBySerialNumber(serial.trim().toUpperCase())
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Téléchargement du certificat (.crt / .pem)
     */
    @GetMapping("/certificates/{serial}/cert")
    public ResponseEntity<byte[]> downloadCertificate(@PathVariable String serial) {
        return certificateRepository.findBySerialNumber(serial.trim().toUpperCase())
                .map(cert -> ResponseEntity.ok()
                        .contentType(MediaType.parseMediaType("application/x-x509-user-cert"))
                        .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + serial + ".crt\"")
                        .body(cert.getCertificatePem().getBytes(StandardCharsets.UTF_8)))
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Téléchargement de la clé privée (.key)
     */
    @GetMapping("/certificates/{serial}/key")
    public ResponseEntity<byte[]> downloadPrivateKey(@PathVariable String serial) {
        return certificateRepository.findBySerialNumber(serial.trim().toUpperCase())
                .filter(cert -> cert.getPrivateKeyPem() != null)
                .map(cert -> ResponseEntity.ok()
                        .contentType(MediaType.parseMediaType("application/pkcs8"))
                        .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + serial + ".key\"")
                        .body(cert.getPrivateKeyPem().getBytes(StandardCharsets.UTF_8)))
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Téléchargement du conteneur PKCS#12 (.p12)
     */
    @GetMapping("/certificates/{serial}/p12")
    public ResponseEntity<byte[]> downloadPkcs12(@PathVariable String serial,
                                                 @RequestParam(defaultValue = "") String password) {
        try {
            var certOpt = certificateRepository.findBySerialNumber(serial.trim().toUpperCase());
            if (certOpt.isEmpty() || certOpt.get().getPrivateKeyPem() == null) {
                return ResponseEntity.notFound().build();
            }

            CertificateEntity certEntity = certOpt.get();
            X509Certificate clientCert = PemUtils.readCertificateFromPem(certEntity.getCertificatePem());
            var privateKey = PemUtils.readPrivateKeyFromPem(certEntity.getPrivateKeyPem());
            X509Certificate caCert = caService.getCaCertificate();

            byte[] p12Bytes = PemUtils.createPkcs12Bundle(
                    certEntity.getCommonName(),
                    privateKey,
                    clientCert,
                    caCert,
                    password
            );

            return ResponseEntity.ok()
                    .contentType(MediaType.parseMediaType("application/x-pkcs12"))
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + serial + ".p12\"")
                    .body(p12Bytes);

        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * Révocation d'un certificat avec motif RFC 5280
     */
    @PostMapping("/certificates/revoke")
    public ResponseEntity<?> revokeCertificate(@Valid @RequestBody RevokeCertificateRequest request) {
        try {
            CertificateEntity revoked = crlService.revokeCertificate(request);
            return ResponseEntity.ok(revoked);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Téléchargement direct de la CRL (point de distribution RFC 5280)
     */
    @GetMapping("/crl/download")
    public ResponseEntity<byte[]> downloadCrl(@RequestParam(defaultValue = "pem") String format) {
        try {
            if ("der".equalsIgnoreCase(format) || "crl".equalsIgnoreCase(format)) {
                byte[] crlDer = crlService.getCrlDer();
                return ResponseEntity.ok()
                        .contentType(MediaType.parseMediaType("application/pkix-crl"))
                        .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"crl.crl\"")
                        .body(crlDer);
            } else {
                byte[] crlPemBytes = crlService.getCrlPem().getBytes(StandardCharsets.UTF_8);
                return ResponseEntity.ok()
                        .contentType(MediaType.parseMediaType("application/x-pem-file"))
                        .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"crl.pem\"")
                        .body(crlPemBytes);
            }
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * Régénération manuelle de la CRL
     */
    @PostMapping("/crl/generate")
    public ResponseEntity<?> generateCrl() {
        try {
            CrlEntity crl = crlService.generateAndPublishCrl();
            return ResponseEntity.ok(crl);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Validation d'un certificat (cryptographie + dates + CRL)
     */
    @PostMapping("/certificates/validate")
    public ResponseEntity<ValidationResult> validateCertificate(@RequestBody Map<String, String> body) {
        String pem = body.get("certificatePem");
        ValidationResult result = validationService.validateCertificate(pem);
        return ResponseEntity.ok(result);
    }

    /**
     * Test de vérification via OpenSSL CLI
     */
    @GetMapping("/openssl/verify/{serial}")
    public ResponseEntity<?> verifyWithOpenSsl(@PathVariable String serial,
                                               @RequestParam(defaultValue = "true") boolean checkCrl) {
        return ResponseEntity.ok(openSslVerificationService.runOpenSslVerify(serial.trim().toUpperCase(), checkCrl));
    }
}
