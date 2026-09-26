package com.ccn.pki.service;

import com.ccn.pki.config.PkiProperties;
import com.ccn.pki.dto.IssueCertificateRequest;
import com.ccn.pki.dto.IssueCsrRequest;
import com.ccn.pki.model.CaEntity;
import com.ccn.pki.model.CertificateEntity;
import com.ccn.pki.model.CertificateStatus;
import com.ccn.pki.model.CertificateType;
import com.ccn.pki.repository.CertificateRepository;
import com.ccn.pki.util.PemUtils;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;

/**
 * ===================================================================
 * Service d'Émission et de Signature de Certificats X.509 v3
 * ===================================================================
 * Gère l'émission complète de certificats clients et serveurs :
 * - Mode Direct : Génération de la biclé RSA + Certificat signé par la Root CA.
 * - Mode CSR (PKCS#10) : Signature de la clé publique fournie par le client.
 * - Injection des extensions X.509 v3 (Basic Constraints, Key Usage, SAN, CRL DP).
 */
@Service
public class CertificateIssuingService {

    private static final Logger log = LoggerFactory.getLogger(CertificateIssuingService.class);
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String BC_PROVIDER = "BC";

    private final CaService caService;
    private final KeyGenerationService keyGenerationService;
    private final CertificateRepository certificateRepository;
    private final PkiProperties pkiProperties;

    public CertificateIssuingService(CaService caService,
                                     KeyGenerationService keyGenerationService,
                                     CertificateRepository certificateRepository,
                                     PkiProperties pkiProperties) {
        this.caService = caService;
        this.keyGenerationService = keyGenerationService;
        this.certificateRepository = certificateRepository;
        this.pkiProperties = pkiProperties;
    }

    /**
     * Émet un nouveau certificat avec génération de biclé par la PKI
     */
    @Transactional
    public CertificateEntity issueCertificate(IssueCertificateRequest request) throws Exception {
        if (!caService.isCaInitialized()) {
            throw new IllegalStateException("L'Autorité Racine (Root CA) n'est pas initialisée.");
        }

        log.info("Émission d'un certificat pour CN='{}', Type={}", request.getCommonName(), request.getType());

        // 1. Génération de la biclé du client
        KeyPair clientKeyPair = keyGenerationService.generateRsaKeyPair(request.getKeySize() > 0 ? request.getKeySize() : 2048);

        // 2. Construction du Distinguished Name (Subject DN)
        X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        nameBuilder.addRDN(BCStyle.CN, request.getCommonName());
        if (StringUtils.hasText(request.getOrganization())) {
            nameBuilder.addRDN(BCStyle.O, request.getOrganization());
        }
        if (StringUtils.hasText(request.getOrganizationalUnit())) {
            nameBuilder.addRDN(BCStyle.OU, request.getOrganizationalUnit());
        }
        if (StringUtils.hasText(request.getCountry())) {
            nameBuilder.addRDN(BCStyle.C, request.getCountry());
        }
        if (StringUtils.hasText(request.getEmail())) {
            nameBuilder.addRDN(BCStyle.EmailAddress, request.getEmail());
        }
        X500Name subject = nameBuilder.build();

        // 3. Signature du certificat par la Root CA
        CertificateEntity entity = signAndSaveCertificate(
                subject,
                clientKeyPair.getPublic(),
                clientKeyPair,
                null,
                request.getType(),
                request.getValidityDays(),
                request.getSubjectAlternativeNames(),
                request.getCommonName(),
                request.getOrganization(),
                request.getOrganizationalUnit(),
                request.getCountry(),
                request.getEmail()
        );

        return entity;
    }

    /**
     * Émet un certificat à partir d'une demande de signature CSR (PKCS#10)
     */
    @Transactional
    public CertificateEntity issueCertificateFromCsr(IssueCsrRequest request) throws Exception {
        if (!caService.isCaInitialized()) {
            throw new IllegalStateException("L'Autorité Racine (Root CA) n'est pas initialisée.");
        }

        log.info("Traitement d'une CSR PKCS#10 pour signature...");

        // 1. Parser la CSR
        PKCS10CertificationRequest csr = PemUtils.readCsrFromPem(request.getCsrPem());
        JcaPKCS10CertificationRequest jcaCsr = new JcaPKCS10CertificationRequest(csr).setProvider(BC_PROVIDER);

        // 2. Vérifier la preuve de possession (signature interne de la CSR)
        boolean validCsr = jcaCsr.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC_PROVIDER).build(jcaCsr.getPublicKey()));
        if (!validCsr) {
            throw new IllegalArgumentException("La signature cryptographique de la CSR est invalide ! Preuve de possession échouée.");
        }

        PublicKey clientPublicKey = jcaCsr.getPublicKey();
        X500Name subject = csr.getSubject();

        String cn = PemUtils.extractRdn(subject, BCStyle.CN);
        String org = PemUtils.extractRdn(subject, BCStyle.O);
        String ou = PemUtils.extractRdn(subject, BCStyle.OU);
        String c = PemUtils.extractRdn(subject, BCStyle.C);
        String email = PemUtils.extractRdn(subject, BCStyle.EmailAddress);

        // 3. Signature et enregistrement (la clé privée n'est pas connue du serveur dans le cas CSR)
        return signAndSaveCertificate(
                subject,
                clientPublicKey,
                null,
                request.getCsrPem(),
                request.getType(),
                request.getValidityDays(),
                request.getSubjectAlternativeNames(),
                cn, org, ou, c, email
        );
    }

    /**
     * Méthode pivot de signature X.509 v3 et injection des extensions conformes RFC 5280
     */
    private CertificateEntity signAndSaveCertificate(
            X500Name subject,
            PublicKey clientPublicKey,
            KeyPair clientKeyPair,
            String csrPem,
            CertificateType type,
            int validityDays,
            String sanInput,
            String cn, String org, String ou, String c, String email
    ) throws Exception {

        X509Certificate caCert = caService.getCaCertificate();
        KeyPair caKeyPair = caService.getCaKeyPair();
        X500Name issuer = new org.bouncycastle.cert.jcajce.JcaX509CertificateHolder(caCert).getSubject();

        BigInteger serialNumber = new BigInteger(64, new SecureRandom());

        long nowMillis = System.currentTimeMillis();
        Date notBefore = new Date(nowMillis - (24L * 60 * 60 * 1000));
        Date notAfter = Date.from(LocalDateTime.now().plusDays(validityDays > 0 ? validityDays : 365).atZone(ZoneId.systemDefault()).toInstant());

        // 1. Initialiser le constructeur de certificat X.509 v3
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                serialNumber,
                notBefore,
                notAfter,
                subject,
                clientPublicKey
        );

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        // --- Extension 1 : Basic Constraints (Critique) ---
        // isCA = false : indique formellement qu'il s'agit d'un certificat d'entité finale (End Entity)
        certBuilder.addExtension(
                Extension.basicConstraints,
                true,
                new BasicConstraints(false)
        );

        // --- Extension 2 : Key Usage (Critique) selon le type ---
        int keyUsageMask;
        KeyPurposeId[] extendedKeyUsage;

        switch (type) {
            case SERVER -> {
                keyUsageMask = KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.keyAgreement;
                extendedKeyUsage = new KeyPurposeId[]{
                        KeyPurposeId.id_kp_serverAuth,
                        KeyPurposeId.id_kp_clientAuth
                };
            }
            case CODE_SIGNING -> {
                keyUsageMask = KeyUsage.digitalSignature;
                extendedKeyUsage = new KeyPurposeId[]{
                        KeyPurposeId.id_kp_codeSigning
                };
            }
            case CLIENT -> {
                keyUsageMask = KeyUsage.digitalSignature | KeyUsage.keyEncipherment;
                extendedKeyUsage = new KeyPurposeId[]{
                        KeyPurposeId.id_kp_clientAuth,
                        KeyPurposeId.id_kp_emailProtection
                };
            }
            default -> {
                keyUsageMask = KeyUsage.digitalSignature | KeyUsage.keyEncipherment;
                extendedKeyUsage = new KeyPurposeId[]{KeyPurposeId.id_kp_clientAuth};
            }
        }

        certBuilder.addExtension(
                Extension.keyUsage,
                true,
                new KeyUsage(keyUsageMask)
        );

        // --- Extension 3 : Extended Key Usage ---
        certBuilder.addExtension(
                Extension.extendedKeyUsage,
                false,
                new ExtendedKeyUsage(extendedKeyUsage)
        );

        // --- Extension 4 : Subject Key Identifier ---
        certBuilder.addExtension(
                Extension.subjectKeyIdentifier,
                false,
                extUtils.createSubjectKeyIdentifier(clientPublicKey)
        );

        // --- Extension 5 : Authority Key Identifier ---
        certBuilder.addExtension(
                Extension.authorityKeyIdentifier,
                false,
                extUtils.createAuthorityKeyIdentifier(caCert.getPublicKey())
        );

        // --- Extension 6 : CRL Distribution Point (RFC 5280) ---
        // Permet aux validateurs et à OpenSSL de localiser automatiquement la CRL
        String crlUrl = pkiProperties.getCrl().getDistributionPoint();
        if (StringUtils.hasText(crlUrl)) {
            GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, crlUrl);
            DistributionPointName dpn = new DistributionPointName(new GeneralNames(gn));
            DistributionPoint distPoint = new DistributionPoint(dpn, null, null);
            certBuilder.addExtension(
                    Extension.cRLDistributionPoints,
                    false,
                    new CRLDistPoint(new DistributionPoint[]{distPoint})
            );
        }

        // --- Extension 7 : Subject Alternative Names (SAN) ---
        // Essentiel pour la conformité TLS moderne (RFC 2818 / RFC 5280)
        List<GeneralName> sanList = new ArrayList<>();
        if (StringUtils.hasText(sanInput)) {
            String[] sans = sanInput.split(",");
            for (String s : sans) {
                String trimmed = s.trim();
                if (!trimmed.isEmpty()) {
                    if (isIpAddress(trimmed)) {
                        sanList.add(new GeneralName(GeneralName.iPAddress, trimmed));
                    } else {
                        sanList.add(new GeneralName(GeneralName.dNSName, trimmed));
                    }
                }
            }
        } else if (type == CertificateType.SERVER && StringUtils.hasText(cn)) {
            // Par défaut pour un serveur, ajouter le CN comme SAN DNS
            if (isIpAddress(cn)) {
                sanList.add(new GeneralName(GeneralName.iPAddress, cn));
            } else {
                sanList.add(new GeneralName(GeneralName.dNSName, cn));
            }
        }

        if (!sanList.isEmpty()) {
            GeneralNames generalNames = new GeneralNames(sanList.toArray(new GeneralName[0]));
            certBuilder.addExtension(
                    Extension.subjectAlternativeName,
                    false,
                    generalNames
            );
        }

        // 2. Signature par la Root CA
        ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .setProvider(BC_PROVIDER)
                .build(caKeyPair.getPrivate());

        X509CertificateHolder holder = certBuilder.build(signer);
        X509Certificate issuedCert = new JcaX509CertificateConverter()
                .setProvider(BC_PROVIDER)
                .getCertificate(holder);

        // Validation cryptographique immédiate de la signature par la clé publique de la CA
        issuedCert.verify(caCert.getPublicKey());

        // 3. Conversions PEM
        String certPem = PemUtils.toPem(issuedCert);
        String privKeyPem = clientKeyPair != null ? PemUtils.toPem(clientKeyPair.getPrivate()) : null;
        String pubKeyPem = PemUtils.toPem(clientPublicKey);
        String serialHex = PemUtils.formatSerialNumberHex(serialNumber);

        // 4. Enregistrement en base de données
        CertificateEntity entity = new CertificateEntity();
        entity.setSerialNumber(serialHex);
        entity.setSubjectDn(subject.toString());
        entity.setCommonName(cn);
        entity.setOrganization(org);
        entity.setOrganizationalUnit(ou);
        entity.setCountry(c);
        entity.setEmail(email);
        entity.setIssuerDn(issuer.toString());
        entity.setNotBefore(notBefore.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime());
        entity.setNotAfter(notAfter.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime());
        entity.setType(type);
        entity.setStatus(CertificateStatus.ACTIVE);
        entity.setSubjectAlternativeNames(sanInput);
        entity.setCertificatePem(certPem);
        entity.setPrivateKeyPem(privKeyPem);
        entity.setPublicKeyPem(pubKeyPem);
        entity.setCsrPem(csrPem);
        entity.setSha256Fingerprint(PemUtils.getSha256Fingerprint(issuedCert));
        entity.setKeyAlgorithm("RSA");
        entity.setKeySize(clientPublicKey.getEncoded().length > 300 ? 2048 : 1024);
        entity.setSignatureAlgorithm(SIGNATURE_ALGORITHM);
        entity.setIssuedAt(LocalDateTime.now());

        entity = certificateRepository.save(entity);

        // 5. Sauvegarde sur disque
        saveCertificateFiles(entity, issuedCert, clientKeyPair, caCert);

        log.info("Certificat émis avec succès : Serial Hex='{}', Subject='{}'", serialHex, subject);
        return entity;
    }

    /**
     * Sauvegarde les fichiers de certificats et clés sur le système de fichiers
     */
    private void saveCertificateFiles(CertificateEntity entity, X509Certificate cert, KeyPair keyPair, X509Certificate caCert) {
        try {
            Path certPath = pkiProperties.getStorage().getCertsDir().resolve(entity.getSerialNumber() + ".crt");
            Files.writeString(certPath, entity.getCertificatePem(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

            if (keyPair != null) {
                Path keyPath = pkiProperties.getStorage().getKeysDir().resolve(entity.getSerialNumber() + ".key");
                Files.writeString(keyPath, entity.getPrivateKeyPem(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

                // Sauvegarde également du conteneur PKCS#12 sans mot de passe par défaut
                byte[] p12Bytes = PemUtils.createPkcs12Bundle(entity.getCommonName(), keyPair.getPrivate(), cert, caCert, "");
                Path p12Path = pkiProperties.getStorage().getCertsDir().resolve(entity.getSerialNumber() + ".p12");
                Files.write(p12Path, p12Bytes, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            }
        } catch (Exception e) {
            log.warn("Impossible d'écrire les fichiers du certificat {} sur disque : {}", entity.getSerialNumber(), e.getMessage());
        }
    }

    private boolean isIpAddress(String text) {
        return text.matches("^(\\d{1,3}\\.){3}\\d{1,3}$");
    }
}
