package com.ccn.pki.service;

import com.ccn.pki.config.PkiProperties;
import com.ccn.pki.dto.RevokeCertificateRequest;
import com.ccn.pki.model.*;
import com.ccn.pki.repository.CertificateRepository;
import com.ccn.pki.repository.CrlRepository;
import com.ccn.pki.repository.RevocationRepository;
import com.ccn.pki.util.PemUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;
import java.util.Optional;

/**
 * ===================================================================
 * Service de Gestion des Révocations et Émission de la CRL (RFC 5280)
 * ===================================================================
 * Gère la révocation de certificats émis avec motif standardisé et
 * génère la Liste de Révocation de Certificats (CRL) X.509 v2 signée
 * par l'Autorité Racine (Root CA).
 */
@Service
public class CrlService {

    private static final Logger log = LoggerFactory.getLogger(CrlService.class);
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String BC_PROVIDER = "BC";

    private final CaService caService;
    private final CertificateRepository certificateRepository;
    private final RevocationRepository revocationRepository;
    private final CrlRepository crlRepository;
    private final PkiProperties pkiProperties;

    // Cache mémoire de la CRL courante
    private byte[] cachedCrlDer;
    private String cachedCrlPem;
    private X509CRL cachedX509Crl;

    public CrlService(CaService caService,
                      CertificateRepository certificateRepository,
                      RevocationRepository revocationRepository,
                      CrlRepository crlRepository,
                      PkiProperties pkiProperties) {
        this.caService = caService;
        this.certificateRepository = certificateRepository;
        this.revocationRepository = revocationRepository;
        this.crlRepository = crlRepository;
        this.pkiProperties = pkiProperties;
    }

    /**
     * Révoque un certificat actif et publie immédiatement une CRL mise à jour
     */
    @Transactional
    public synchronized CertificateEntity revokeCertificate(RevokeCertificateRequest request) throws Exception {
        String serialNumber = request.getSerialNumber().trim().toUpperCase();
        log.info("Demande de révocation pour le certificat Serial='{}', Motif='{}'", serialNumber, request.getReason());

        CertificateEntity cert = certificateRepository.findBySerialNumber(serialNumber)
                .orElseThrow(() -> new IllegalArgumentException("Certificat introuvable avec le numéro de série : " + serialNumber));

        if (cert.getStatus() == CertificateStatus.REVOKED) {
            throw new IllegalStateException("Ce certificat est déjà révoqué depuis le " + cert.getRevokedAt());
        }

        LocalDateTime now = LocalDateTime.now();

        // 1. Mettre à jour l'entité certificat
        cert.setStatus(CertificateStatus.REVOKED);
        cert.setRevokedAt(now);
        cert.setRevocationReason(request.getReason());
        certificateRepository.save(cert);

        // 2. Enregistrer l'entrée de révocation
        RevocationEntity revocation = new RevocationEntity();
        revocation.setSerialNumber(serialNumber);
        revocation.setRevocationDate(now);
        revocation.setReason(request.getReason());
        revocation.setComments(request.getComments());
        revocation.setCertificate(cert);
        revocationRepository.save(revocation);

        // 3. Regénérer et signer la CRL X.509 v2
        generateAndPublishCrl();

        log.info("Certificat '{}' révoqué avec succès et CRL mise à jour.", serialNumber);
        return cert;
    }

    /**
     * Génère et publie une nouvelle version signée de la CRL X.509 v2
     */
    @Transactional
    public synchronized CrlEntity generateAndPublishCrl() throws Exception {
        if (!caService.isCaInitialized()) {
            throw new IllegalStateException("L'Autorité Racine (Root CA) n'est pas initialisée.");
        }

        X509Certificate caCert = caService.getCaCertificate();
        KeyPair caKeyPair = caService.getCaKeyPair();
        X500Name issuer = new org.bouncycastle.cert.jcajce.JcaX509CertificateHolder(caCert).getSubject();

        Date thisUpdate = new Date();
        int validityDays = pkiProperties.getCrl().getValidityDays();
        Date nextUpdate = Date.from(LocalDateTime.now().plusDays(validityDays > 0 ? validityDays : 30)
                .atZone(ZoneId.systemDefault()).toInstant());

        // 1. Déterminer le numéro séquentiel de CRL (CRLNumber)
        long crlNumber = crlRepository.findFirstByOrderByCrlNumberDesc()
                .map(c -> c.getCrlNumber() + 1)
                .orElse(1L);

        // 2. Créer le constructeur X.509 v2 CRL
        X509v2CRLBuilder crlBuilder = new JcaX509v2CRLBuilder(caCert, thisUpdate);
        crlBuilder.setNextUpdate(nextUpdate);

        // 3. Ajouter toutes les entrées révoquées
        List<RevocationEntity> allRevocations = revocationRepository.findAll();
        for (RevocationEntity rev : allRevocations) {
            BigInteger serial = new BigInteger(rev.getSerialNumber(), 16);
            Date revDate = Date.from(rev.getRevocationDate().atZone(ZoneId.systemDefault()).toInstant());
            int reasonCode = rev.getReason() != null ? rev.getReason().getCode() : CRLReason.unspecified;

            // Ajout du certificat révoqué avec la date et le motif de révocation RFC 5280
            crlBuilder.addCRLEntry(serial, revDate, reasonCode);
        }

        // 4. Extensions standard de la CRL
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        // Extension CRLNumber (Non critique) : identifiant séquentiel de la CRL
        crlBuilder.addExtension(
                Extension.cRLNumber,
                false,
                new CRLNumber(BigInteger.valueOf(crlNumber))
        );

        // Extension AuthorityKeyIdentifier (Non critique) : lien vers la clé publique de la CA
        crlBuilder.addExtension(
                Extension.authorityKeyIdentifier,
                false,
                extUtils.createAuthorityKeyIdentifier(caCert.getPublicKey())
        );

        // 5. Signature de la CRL par la Root CA
        ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .setProvider(BC_PROVIDER)
                .build(caKeyPair.getPrivate());

        X509CRLHolder crlHolder = crlBuilder.build(signer);
        X509CRL x509Crl = new JcaX509CRLConverter()
                .setProvider(BC_PROVIDER)
                .getCRL(crlHolder);

        // Vérification de la signature de la CRL par la clé publique de la Root CA
        x509Crl.verify(caCert.getPublicKey());

        // 6. Conversions et persistance
        String crlPem = PemUtils.toPem(x509Crl);
        byte[] crlDer = x509Crl.getEncoded();

        CrlEntity crlEntity = new CrlEntity();
        crlEntity.setCrlNumber(crlNumber);
        crlEntity.setThisUpdate(thisUpdate.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime());
        crlEntity.setNextUpdate(nextUpdate.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime());
        crlEntity.setCrlPem(crlPem);
        crlEntity.setRevokedCount(allRevocations.size());
        crlEntity.setCreatedAt(LocalDateTime.now());

        crlEntity = crlRepository.save(crlEntity);

        // 7. Mise en cache
        this.cachedCrlDer = crlDer;
        this.cachedCrlPem = crlPem;
        this.cachedX509Crl = x509Crl;

        // 8. Écriture sur disque pour téléchargement et validation externe OpenSSL
        Path crlDir = pkiProperties.getStorage().getCrlDir();
        Files.writeString(crlDir.resolve("crl.pem"), crlPem, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        Files.write(crlDir.resolve("crl.crl"), crlDer, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

        log.info("CRL v2 signée et publiée : CRL #{} avec {} entrée(s) révoquée(s)", crlNumber, allRevocations.size());
        return crlEntity;
    }

    /**
     * Récupère la CRL au format PEM
     */
    public synchronized String getCrlPem() throws Exception {
        if (cachedCrlPem == null) {
            Optional<CrlEntity> latest = crlRepository.findFirstByOrderByCrlNumberDesc();
            if (latest.isPresent()) {
                cachedCrlPem = latest.get().getCrlPem();
                cachedCrlDer = PemUtils.readCrlFromPemOrDer(cachedCrlPem.getBytes()).getEncoded();
                cachedX509Crl = PemUtils.readCrlFromPemOrDer(cachedCrlDer);
            } else {
                generateAndPublishCrl();
            }
        }
        return cachedCrlPem;
    }

    /**
     * Récupère la CRL au format binaire DER
     */
    public synchronized byte[] getCrlDer() throws Exception {
        if (cachedCrlDer == null) {
            getCrlPem(); // Déclenche le chargement ou la génération
        }
        return cachedCrlDer;
    }

    /**
     * Récupère l'objet X509CRL parsé
     */
    public synchronized X509CRL getX509Crl() throws Exception {
        if (cachedX509Crl == null) {
            getCrlPem();
        }
        return cachedX509Crl;
    }

    /**
     * Vérifie si un numéro de série est présent dans la CRL
     */
    public boolean isRevoked(BigInteger serialNumber) {
        try {
            X509CRL crl = getX509Crl();
            return crl != null && crl.getRevokedCertificate(serialNumber) != null;
        } catch (Exception e) {
            log.error("Erreur lors de la vérification CRL pour le numéro de série {}: {}", serialNumber, e.getMessage());
            return revocationRepository.existsBySerialNumber(PemUtils.formatSerialNumberHex(serialNumber));
        }
    }
}
