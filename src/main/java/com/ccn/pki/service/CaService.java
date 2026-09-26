package com.ccn.pki.service;

import com.ccn.pki.config.PkiProperties;
import com.ccn.pki.model.CaEntity;
import com.ccn.pki.repository.CaRepository;
import com.ccn.pki.util.PemUtils;
import jakarta.annotation.PostConstruct;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
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
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.Optional;

/**
 * ===================================================================
 * Service de Gestion de l'Autorité de Certification Racine (Root CA)
 * ===================================================================
 * Gère l'initialisation, la génération de la biclé asymétrique,
 * la création du certificat auto-signé conforme RFC 5280 et le stockage.
 */
@Service
public class CaService {

    private static final Logger log = LoggerFactory.getLogger(CaService.class);
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String BC_PROVIDER = "BC";

    private final CaRepository caRepository;
    private final KeyGenerationService keyGenerationService;
    private final PkiProperties pkiProperties;

    // Cache mémoire pour accès rapide lors de la signature des certificats clients et CRL
    private KeyPair cachedCaKeyPair;
    private X509Certificate cachedCaCertificate;
    private CaEntity cachedCaEntity;

    public CaService(CaRepository caRepository,
                     KeyGenerationService keyGenerationService,
                     PkiProperties pkiProperties) {
        this.caRepository = caRepository;
        this.keyGenerationService = keyGenerationService;
        this.pkiProperties = pkiProperties;
    }

    /**
     * Initialisation au démarrage de l'application :
     * Crée les dossiers de stockage nécessaires et charge ou crée la Root CA par défaut.
     */
    @PostConstruct
    public void init() {
        try {
            createStorageDirectories();
            loadOrInitRootCa();
        } catch (Exception e) {
            log.error("Erreur lors de l'initialisation du service Root CA : {}", e.getMessage(), e);
        }
    }

    /**
     * Crée l'arborescence des répertoires de persistance pour les certificats, clés et CRL
     */
    public void createStorageDirectories() throws Exception {
        Files.createDirectories(pkiProperties.getStorage().getCaDir());
        Files.createDirectories(pkiProperties.getStorage().getCertsDir());
        Files.createDirectories(pkiProperties.getStorage().getKeysDir());
        Files.createDirectories(pkiProperties.getStorage().getCrlDir());
        Files.createDirectories(pkiProperties.getStorage().getCaDir().resolve("../db"));
    }

    /**
     * Charge la Root CA existante en base ou génère une Root CA initiale
     */
    @Transactional
    public synchronized void loadOrInitRootCa() throws Exception {
        Optional<CaEntity> optionalCa = caRepository.findFirstByActiveTrueOrderByCreatedAtDesc();
        if (optionalCa.isPresent()) {
            CaEntity ca = optionalCa.get();
            this.cachedCaEntity = ca;
            this.cachedCaCertificate = PemUtils.readCertificateFromPem(ca.getCertificatePem());
            PrivateKey privateKey = PemUtils.readPrivateKeyFromPem(ca.getPrivateKeyPem());
            this.cachedCaKeyPair = new KeyPair(this.cachedCaCertificate.getPublicKey(), privateKey);
            log.info("Root CA chargée avec succès : {}", ca.getSubjectDn());
            syncFilesToDisk(ca);
        } else {
            log.info("Aucune Root CA active trouvée. Initialisation automatique de la Root CA par défaut...");
            initializeRootCa(
                    pkiProperties.getCa().getDefaultDn(),
                    pkiProperties.getCa().getValidityYears(),
                    pkiProperties.getCa().getKeySize()
            );
        }
    }

    /**
     * Génère une nouvelle Autorité de Certification Racine (Root CA) auto-signée.
     *
     * @param subjectDn     Le Distinguished Name de la CA (ex: CN=CCN Root CA, O=ENSET...)
     * @param validityYears Durée de validité en années (ex: 10 ans)
     * @param keySize       Taille de la clé RSA en bits (ex: 4096)
     * @return L'entité CaEntity sauvegardée
     */
    @Transactional
    public synchronized CaEntity initializeRootCa(String subjectDn, int validityYears, int keySize) throws Exception {
        log.info("Génération d'une nouvelle Root CA : DN='{}', Validité={} ans, Clé={} bits",
                subjectDn, validityYears, keySize);

        // 1. Désactiver toute ancienne CA active
        caRepository.findAll().forEach(ca -> {
            ca.setActive(false);
            caRepository.save(ca);
        });

        // 2. Générer la biclé RSA (4096 bits recommandé pour une Root CA)
        KeyPair caKeyPair = keyGenerationService.generateRsaKeyPair(keySize);

        // 3. Définir les dates de validité
        long nowMillis = System.currentTimeMillis();
        // Recul de 24h pour éviter les problèmes de synchronisation d'horloge (clock skew)
        Date notBefore = new Date(nowMillis - (24L * 60 * 60 * 1000));
        Date notAfter = Date.from(LocalDateTime.now().plusYears(validityYears).atZone(ZoneId.systemDefault()).toInstant());

        // 4. Numéro de série unique aléatoire (64 bits positifs)
        BigInteger serialNumber = new BigInteger(64, new SecureRandom());

        // 5. Pour une Root CA auto-signée, Issuer = Subject
        X500Name issuer = new X500Name(subjectDn);
        X500Name subject = new X500Name(subjectDn);

        // 6. Construction du certificat X.509 v3
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                serialNumber,
                notBefore,
                notAfter,
                subject,
                caKeyPair.getPublic()
        );

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        // --- Extension 1 : Basic Constraints (Critique) ---
        // isCA = true, pathLenConstraint = non limité (indique que ce certificat est une autorité racine)
        certBuilder.addExtension(
                Extension.basicConstraints,
                true,
                new BasicConstraints(true)
        );

        // --- Extension 2 : Key Usage (Critique) ---
        // Autorise la signature de certificats (keyCertSign) et de listes de révocation (cRLSign)
        certBuilder.addExtension(
                Extension.keyUsage,
                true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.digitalSignature)
        );

        // --- Extension 3 : Subject Key Identifier (Non critique) ---
        // Identifiant unique calculé à partir du hash de la clé publique de la CA
        certBuilder.addExtension(
                Extension.subjectKeyIdentifier,
                false,
                extUtils.createSubjectKeyIdentifier(caKeyPair.getPublic())
        );

        // --- Extension 4 : Authority Key Identifier (Non critique) ---
        // Pour une Root CA auto-signée, correspond à son propre SubjectKeyIdentifier
        certBuilder.addExtension(
                Extension.authorityKeyIdentifier,
                false,
                extUtils.createAuthorityKeyIdentifier(caKeyPair.getPublic())
        );

        // 7. Signature du certificat avec la clé privée de la Root CA (Auto-signature)
        ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .setProvider(BC_PROVIDER)
                .build(caKeyPair.getPrivate());

        X509CertificateHolder certHolder = certBuilder.build(signer);
        X509Certificate rootCert = new JcaX509CertificateConverter()
                .setProvider(BC_PROVIDER)
                .getCertificate(certHolder);

        // Vérification d'intégrité de l'auto-signature
        rootCert.verify(caKeyPair.getPublic());

        // 8. Conversion en PEM
        String certPem = PemUtils.toPem(rootCert);
        String privKeyPem = PemUtils.toPem(caKeyPair.getPrivate());
        String pubKeyPem = PemUtils.toPem(caKeyPair.getPublic());

        // 9. Persistance en base de données
        CaEntity caEntity = new CaEntity();
        caEntity.setSubjectDn(subjectDn);
        caEntity.setIssuerDn(subjectDn);
        caEntity.setSerialNumber(PemUtils.formatSerialNumberHex(serialNumber));
        caEntity.setNotBefore(notBefore.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime());
        caEntity.setNotAfter(notAfter.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime());
        caEntity.setKeyAlgorithm("RSA");
        caEntity.setKeySize(keySize);
        caEntity.setSignatureAlgorithm(SIGNATURE_ALGORITHM);
        caEntity.setSha256Fingerprint(PemUtils.getSha256Fingerprint(rootCert));
        caEntity.setSha1Fingerprint(PemUtils.getSha1Fingerprint(rootCert));
        caEntity.setCertificatePem(certPem);
        caEntity.setPrivateKeyPem(privKeyPem);
        caEntity.setPublicKeyPem(pubKeyPem);
        caEntity.setActive(true);
        caEntity.setCreatedAt(LocalDateTime.now());

        caEntity = caRepository.save(caEntity);

        // 10. Mise en cache mémoire
        this.cachedCaKeyPair = caKeyPair;
        this.cachedCaCertificate = rootCert;
        this.cachedCaEntity = caEntity;

        // 11. Écriture sur disque pour usage externe (OpenSSL, etc.)
        syncFilesToDisk(caEntity);

        log.info("Root CA générée et persistée avec succès ! Serial Hex: {}", caEntity.getSerialNumber());
        return caEntity;
    }

    /**
     * Écrit les fichiers rootCA.crt, rootCA.key et rootCA.pem sur le disque
     */
    private void syncFilesToDisk(CaEntity caEntity) {
        try {
            Path caDir = pkiProperties.getStorage().getCaDir();
            Files.writeString(caDir.resolve("rootCA.crt"), caEntity.getCertificatePem(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            Files.writeString(caDir.resolve("rootCA.pem"), caEntity.getCertificatePem(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            Files.writeString(caDir.resolve("rootCA.key"), caEntity.getPrivateKeyPem(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            Files.writeString(caDir.resolve("rootCA_public.key"), caEntity.getPublicKeyPem(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        } catch (Exception e) {
            log.warn("Impossible d'écrire les fichiers Root CA sur disque : {}", e.getMessage());
        }
    }

    public synchronized X509Certificate getCaCertificate() {
        return cachedCaCertificate;
    }

    public synchronized KeyPair getCaKeyPair() {
        return cachedCaKeyPair;
    }

    public synchronized CaEntity getActiveCa() {
        return cachedCaEntity;
    }

    public boolean isCaInitialized() {
        return cachedCaCertificate != null && cachedCaKeyPair != null;
    }
}
