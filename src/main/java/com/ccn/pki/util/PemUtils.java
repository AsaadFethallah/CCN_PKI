package com.ccn.pki.util;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HexFormat;

/**
 * ===================================================================
 * Utilitaire Cryptographique PEM & X.509 (Bouncy Castle / Java Security)
 * ===================================================================
 * Fournit les fonctions d'encodage, décodage, sérialisation et calcul
 * d'empreintes numériques conformes aux standards RFC 5280 et PKCS.
 */
public final class PemUtils {

    private static final String BC_PROVIDER = "BC";

    private PemUtils() {
    }

    /**
     * Convertit un objet en chaîne encodée au format PEM (RFC 7468)
     */
    public static String toPem(Object obj) throws IOException {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(sw)) {
            writer.writeObject(obj);
        }
        return sw.toString();
    }

    /**
     * Lit un certificat X.509 à partir d'une chaîne PEM
     */
    public static X509Certificate readCertificateFromPem(String pemContent) throws Exception {
        try (PEMParser parser = new PEMParser(new StringReader(pemContent))) {
            Object obj = parser.readObject();
            if (obj instanceof X509CertificateHolder holder) {
                return new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(holder);
            } else if (obj instanceof X509Certificate cert) {
                return cert;
            }
        }
        // Tentative alternative avec CertificateFactory standard si besoin
        CertificateFactory cf = CertificateFactory.getInstance("X.509", BC_PROVIDER);
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(pemContent.getBytes()));
    }

    /**
     * Lit une clé privée à partir d'une chaîne PEM
     */
    public static PrivateKey readPrivateKeyFromPem(String pemContent) throws Exception {
        try (PEMParser parser = new PEMParser(new StringReader(pemContent))) {
            Object obj = parser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(BC_PROVIDER);
            if (obj instanceof PEMKeyPair keyPair) {
                return converter.getPrivateKey(keyPair.getPrivateKeyInfo());
            } else if (obj instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo pki) {
                return converter.getPrivateKey(pki);
            }
        }
        // Fallback pour parsing standard PKCS#8
        try (PemReader pemReader = new PemReader(new StringReader(pemContent))) {
            PemObject pemObject = pemReader.readPemObject();
            if (pemObject != null) {
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pemObject.getContent());
                KeyFactory kf = KeyFactory.getInstance("RSA", BC_PROVIDER);
                return kf.generatePrivate(keySpec);
            }
        }
        throw new IllegalArgumentException("Impossible de parser la clé privée PEM fournie.");
    }

    /**
     * Parse une demande de signature de certificat (CSR / PKCS#10) depuis une chaîne PEM
     */
    public static PKCS10CertificationRequest readCsrFromPem(String pemContent) throws Exception {
        try (PEMParser parser = new PEMParser(new StringReader(pemContent))) {
            Object obj = parser.readObject();
            if (obj instanceof PKCS10CertificationRequest csr) {
                return csr;
            }
            throw new IllegalArgumentException("Le contenu PEM ne correspond pas à une CSR PKCS#10 valide.");
        }
    }

    /**
     * Lit une CRL X.509 à partir d'une chaîne PEM ou DER
     */
    public static X509CRL readCrlFromPemOrDer(byte[] bytes) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", BC_PROVIDER);
        return (X509CRL) cf.generateCRL(new ByteArrayInputStream(bytes));
    }

    /**
     * Génère un conteneur PKCS#12 (.p12 / .pfx) contenant la clé privée et la chaîne de certificats
     */
    public static byte[] createPkcs12Bundle(String alias, PrivateKey privateKey, X509Certificate clientCert, X509Certificate caCert, String password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12", BC_PROVIDER);
        keyStore.load(null, null);

        java.security.cert.Certificate[] chain;
        if (caCert != null) {
            chain = new java.security.cert.Certificate[]{clientCert, caCert};
        } else {
            chain = new java.security.cert.Certificate[]{clientCert};
        }

        char[] passChars = password != null ? password.toCharArray() : "".toCharArray();
        keyStore.setKeyEntry(alias, privateKey, passChars, chain);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        keyStore.store(bos, passChars);
        return bos.toByteArray();
    }

    /**
     * Calcule l'empreinte SHA-256 d'un certificat X.509 au format hexadécimal séparé par des deux-points
     */
    public static String getSha256Fingerprint(X509Certificate certificate) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(certificate.getEncoded());
            return formatFingerprint(digest);
        } catch (Exception e) {
            return "N/A";
        }
    }

    /**
     * Calcule l'empreinte SHA-1 d'un certificat X.509
     */
    public static String getSha1Fingerprint(X509Certificate certificate) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] digest = md.digest(certificate.getEncoded());
            return formatFingerprint(digest);
        } catch (Exception e) {
            return "N/A";
        }
    }

    /**
     * Formate un tableau d'octets d'empreinte en format lisible (XX:YY:ZZ:...)
     */
    private static String formatFingerprint(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            sb.append(String.format("%02X", bytes[i]));
            if (i < bytes.length - 1) {
                sb.append(":");
            }
        }
        return sb.toString();
    }

    /**
     * Formate un BigInteger de numéro de série en représentation hexadécimale majuscule
     */
    public static String formatSerialNumberHex(BigInteger serial) {
        return serial.toString(16).toUpperCase();
    }

    /**
     * Extrait une valeur RDNDN particulière (ex: CN, O, OU, C) d'un X500Name
     */
    public static String extractRdn(X500Name x500Name, org.bouncycastle.asn1.ASN1ObjectIdentifier oid) {
        var rdns = x500Name.getRDNs(oid);
        if (rdns != null && rdns.length > 0) {
            return IETFUtils.valueToString(rdns[0].getFirst().getValue());
        }
        return null;
    }
}
