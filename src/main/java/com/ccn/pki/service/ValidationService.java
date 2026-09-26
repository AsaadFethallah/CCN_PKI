package com.ccn.pki.service;

import com.ccn.pki.dto.ValidationResult;
import com.ccn.pki.model.CertificateStatus;
import com.ccn.pki.model.RevocationReason;
import com.ccn.pki.repository.RevocationRepository;
import com.ccn.pki.util.PemUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.SignatureException;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * ===================================================================
 * Service de Validation et Vérification Cryptographique de Certificats
 * ===================================================================
 * Implémente le moteur d'inspection et de vérification conforme RFC 5280 :
 * 1. Décodage et parsing du certificat X.509
 * 2. Vérification de la période de validité temporelle (notBefore / notAfter)
 * 3. Vérification de la signature cryptographique via la clé publique de la Root CA
 * 4. Contrôle de révocation en temps réel contre la Liste de Révocation (CRL)
 * 5. Extraction détaillée des extensions X.509v3
 */
@Service
public class ValidationService {

    private static final Logger log = LoggerFactory.getLogger(ValidationService.class);
    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss z");

    private final CaService caService;
    private final CrlService crlService;
    private final RevocationRepository revocationRepository;

    public ValidationService(CaService caService,
                             CrlService crlService,
                             RevocationRepository revocationRepository) {
        this.caService = caService;
        this.crlService = crlService;
        this.revocationRepository = revocationRepository;
    }

    /**
     * Valide un certificat à partir de son contenu texte au format PEM
     */
    public ValidationResult validateCertificate(String pemContent) {
        ValidationResult result = new ValidationResult();

        if (pemContent == null || pemContent.trim().isEmpty()) {
            result.setValid(false);
            result.setMessage("Aucun certificat fourni.");
            result.addLog("Erreur : Le contenu PEM fourni est vide.");
            return result;
        }

        try {
            // 1. Parsing du certificat
            X509Certificate cert = PemUtils.readCertificateFromPem(pemContent);
            result.setFormatValid(true);
            result.addLog("[OK] Format X.509 valide détecté et parsé avec succès.");

            // Renseignement des métadonnées
            result.setSubjectDn(cert.getSubjectX500Principal().getName());
            result.setIssuerDn(cert.getIssuerX500Principal().getName());
            result.setSerialNumber(PemUtils.formatSerialNumberHex(cert.getSerialNumber()));
            result.setNotBefore(DATE_FORMAT.format(cert.getNotBefore()));
            result.setNotAfter(DATE_FORMAT.format(cert.getNotAfter()));
            result.setSignatureAlgorithm(cert.getSigAlgName());
            result.setSha256Fingerprint(PemUtils.getSha256Fingerprint(cert));

            // Inspection des extensions X.509 v3
            inspectExtensions(cert, result);

            // 2. Vérification de la validité temporelle
            Date now = new Date();
            boolean isTimeValid = true;

            if (now.before(cert.getNotBefore())) {
                isTimeValid = false;
                result.addLog("[ÉCHEC] Le certificat n'est pas encore valide (notBefore: " + DATE_FORMAT.format(cert.getNotBefore()) + ")");
            } else if (now.after(cert.getNotAfter())) {
                isTimeValid = false;
                result.addLog("[ÉCHEC] Le certificat a expiré le " + DATE_FORMAT.format(cert.getNotAfter()));
            } else {
                result.addLog("[OK] Validité temporelle confirmée : valide du "
                        + DATE_FORMAT.format(cert.getNotBefore()) + " au " + DATE_FORMAT.format(cert.getNotAfter()));
            }
            result.setTimeValid(isTimeValid);

            // 3. Vérification de la signature cryptographique par la Root CA
            X509Certificate rootCa = caService.getCaCertificate();
            boolean isSignatureValid = false;

            if (rootCa == null) {
                result.addLog("[ATTENTION] Aucune Root CA active pour vérifier la signature.");
            } else {
                try {
                    cert.verify(rootCa.getPublicKey());
                    isSignatureValid = true;
                    result.addLog("[OK] Signature cryptographique vérifiée avec succès avec la clé publique de la Root CA ("
                            + rootCa.getSubjectX500Principal().getName() + ").");
                } catch (SignatureException se) {
                    result.addLog("[ÉCHEC] Signature cryptographique INVALIDE ! Le certificat n'a pas été signé par cette CA ou a été altéré.");
                } catch (Exception e) {
                    result.addLog("[ÉCHEC] Erreur lors de la vérification de la signature : " + e.getMessage());
                }
            }
            result.setSignatureValid(isSignatureValid);

            // 4. Vérification de la révocation contre la CRL
            boolean isNotRevoked = true;
            try {
                var crl = crlService.getX509Crl();
                if (crl != null) {
                    X509CRLEntry crlEntry = crl.getRevokedCertificate(cert.getSerialNumber());
                    if (crlEntry != null) {
                        isNotRevoked = false;
                        result.setRevocationDate(DATE_FORMAT.format(crlEntry.getRevocationDate()));

                        // Récupération de la raison RFC 5280
                        String reasonStr = "Non spécifié";
                        byte[] reasonExt = crlEntry.getExtensionValue(Extension.reasonCode.getId());
                        if (reasonExt != null) {
                            try (ASN1InputStream asn1In = new ASN1InputStream(new ByteArrayInputStream(reasonExt))) {
                                ASN1OctetString octetString = (ASN1OctetString) asn1In.readObject();
                                try (ASN1InputStream octetIn = new ASN1InputStream(octetString.getOctets())) {
                                    ASN1Primitive prim = octetIn.readObject();
                                    CRLReason crlReason = CRLReason.getInstance(prim);
                                    for (RevocationReason r : RevocationReason.values()) {
                                        if (r.getCode() == crlReason.getValue().intValue()) {
                                            reasonStr = r.getDescription();
                                            break;
                                        }
                                    }
                                }
                            } catch (Exception ex) {
                                reasonStr = "Code inconnu";
                            }
                        } else {
                            // Recherche en base locale si besoin
                            revocationRepository.findBySerialNumber(result.getSerialNumber())
                                    .ifPresent(r -> result.setRevocationReason(r.getReason().getDescription()));
                        }

                        result.setRevocationReason(reasonStr);
                        result.addLog("[RÉVOQUÉ] Certificat présent dans la CRL ! Date de révocation : "
                                + result.getRevocationDate() + ", Motif : " + reasonStr);
                    } else {
                        result.addLog("[OK] Contrôle CRL : Le certificat ne figure pas dans la liste de révocation.");
                    }
                }
            } catch (Exception e) {
                result.addLog("[ATTENTION] Impossible d'analyser la CRL : " + e.getMessage());
            }
            result.setNotRevoked(isNotRevoked);

            // Synthèse globale du statut
            if (!isSignatureValid) {
                result.setValid(false);
                result.setStatus(CertificateStatus.EXPIRED); // Utilise EXPIRED ou affichage Signature Invalide
                result.setMessage("Signature cryptographique invalide : Ce certificat n'est pas émis par la Root CA.");
            } else if (!isNotRevoked) {
                result.setValid(false);
                result.setStatus(CertificateStatus.REVOKED);
                result.setMessage("Certificat RÉVOQUÉ : Présent dans la liste de révocation (CRL).");
            } else if (!isTimeValid) {
                result.setValid(false);
                result.setStatus(CertificateStatus.EXPIRED);
                result.setMessage("Certificat EXPIRÉ : Période de validité dépassée.");
            } else {
                result.setValid(true);
                result.setStatus(CertificateStatus.ACTIVE);
                result.setMessage("Certificat VALIDE et de confiance (Signé par la Root CA, non révoqué, période valide).");
            }

        } catch (Exception e) {
            log.error("Erreur de parsing/validation du certificat : {}", e.getMessage());
            result.setValid(false);
            result.setFormatValid(false);
            result.setMessage("Erreur lors de la lecture du certificat : " + e.getMessage());
            result.addLog("[ERREUR CRITIQUE] Impossible de lire le certificat : " + e.getMessage());
        }

        return result;
    }

    /**
     * Analyse et extrait les extensions X.509 v3
     */
    private void inspectExtensions(X509Certificate cert, ValidationResult result) {
        // Basic Constraints
        int pathLen = cert.getBasicConstraints();
        if (pathLen >= 0) {
            result.getExtensions().add("Basic Constraints: CA=TRUE (PathLenConstraint=" + (pathLen == Integer.MAX_VALUE ? "Non limité" : pathLen) + ")");
        } else {
            result.getExtensions().add("Basic Constraints: CA=FALSE (Certificat d'entité finale)");
        }

        // Key Usage
        boolean[] keyUsage = cert.getKeyUsage();
        if (keyUsage != null) {
            List<String> usages = new ArrayList<>();
            String[] names = {
                    "digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment",
                    "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"
            };
            for (int i = 0; i < Math.min(keyUsage.length, names.length); i++) {
                if (keyUsage[i]) {
                    usages.add(names[i]);
                }
            }
            result.getExtensions().add("Key Usage: " + String.join(", ", usages));
        }

        // Extended Key Usage
        try {
            List<String> eku = cert.getExtendedKeyUsage();
            if (eku != null && !eku.isEmpty()) {
                result.getExtensions().add("Extended Key Usage (EKU): " + String.join(", ", eku));
            }
        } catch (Exception ignored) {
        }

        // Subject Alternative Names
        try {
            var sans = cert.getSubjectAlternativeNames();
            if (sans != null && !sans.isEmpty()) {
                List<String> sanStrs = new ArrayList<>();
                for (List<?> item : sans) {
                    if (item.size() >= 2) {
                        sanStrs.add(item.get(1).toString());
                    }
                }
                result.getExtensions().add("Subject Alternative Names (SAN): " + String.join(", ", sanStrs));
            }
        } catch (Exception ignored) {
        }
    }
}
