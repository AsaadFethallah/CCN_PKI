package com.ccn.pki;

import com.ccn.pki.dto.IssueCertificateRequest;
import com.ccn.pki.dto.IssueCsrRequest;
import com.ccn.pki.dto.RevokeCertificateRequest;
import com.ccn.pki.dto.ValidationResult;
import com.ccn.pki.model.CaEntity;
import com.ccn.pki.model.CertificateEntity;
import com.ccn.pki.model.CertificateStatus;
import com.ccn.pki.model.CertificateType;
import com.ccn.pki.model.RevocationReason;
import com.ccn.pki.service.CaService;
import com.ccn.pki.service.CertificateIssuingService;
import com.ccn.pki.service.CrlService;
import com.ccn.pki.service.ValidationService;
import com.ccn.pki.util.PemUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ===================================================================
 * Suite de Tests Automatisés : CCN_PKI
 * Valide l'ensemble des fonctionnalités requises par le TP Option B
 * ===================================================================
 */
@SpringBootTest
public class PkiServiceTests {

    @Autowired
    private CaService caService;

    @Autowired
    private CertificateIssuingService certificateIssuingService;

    @Autowired
    private CrlService crlService;

    @Autowired
    private ValidationService validationService;

    @BeforeEach
    void setUp() throws Exception {
        // S'assurer que la Root CA est bien initialisée
        if (!caService.isCaInitialized()) {
            caService.initializeRootCa(
                    "CN=Test CCN Root CA, OU=Security Lab, O=ENSET Mohammedia, C=MA",
                    10,
                    2048
            );
        }
    }

    @Test
    @DisplayName("Test 1 : Initialisation de la Root CA et validation auto-signature")
    void testRootCaInitialization() throws Exception {
        CaEntity ca = caService.getActiveCa();
        assertNotNull(ca, "L'entité Root CA doit exister");
        assertTrue(ca.isActive(), "La Root CA doit être active");

        X509Certificate caCert = caService.getCaCertificate();
        assertNotNull(caCert, "Le certificat X.509 de la Root CA doit être chargé");

        // Vérification de l'auto-signature cryptographique
        assertDoesNotThrow(() -> caCert.verify(caCert.getPublicKey()), "L'auto-signature du certificat racine doit être valide");

        // Vérification de la contrainte BasicConstraints (isCA = true)
        assertTrue(caCert.getBasicConstraints() >= 0, "La Root CA doit avoir l'extension BasicConstraints avec isCA=true");
    }

    @Test
    @DisplayName("Test 2 : Émission d'un certificat client signé par la Root CA")
    void testIssueClientCertificate() throws Exception {
        IssueCertificateRequest req = new IssueCertificateRequest();
        req.setCommonName("etudiant.test.ma");
        req.setOrganization("ENSET Mohammedia");
        req.setOrganizationalUnit("CyberSec");
        req.setCountry("MA");
        req.setEmail("etudiant@enset-media.ac.ma");
        req.setType(CertificateType.CLIENT);
        req.setValidityDays(365);
        req.setKeySize(2048);

        CertificateEntity certEntity = certificateIssuingService.issueCertificate(req);
        assertNotNull(certEntity, "L'entité du certificat émis ne doit pas être nulle");
        assertEquals("etudiant.test.ma", certEntity.getCommonName());
        assertEquals(CertificateStatus.ACTIVE, certEntity.getStatus());
        assertNotNull(certEntity.getCertificatePem(), "Le PEM du certificat ne doit pas être nul");
        assertNotNull(certEntity.getPrivateKeyPem(), "La clé privée doit être disponible en mode direct");

        // Vérification cryptographique de la signature par la clé publique de la Root CA
        X509Certificate clientCert = PemUtils.readCertificateFromPem(certEntity.getCertificatePem());
        X509Certificate caCert = caService.getCaCertificate();
        assertDoesNotThrow(() -> clientCert.verify(caCert.getPublicKey()), "Le certificat client doit être signé par la clé publique de la Root CA");

        // Vérification de la contrainte BasicConstraints (isCA = false)
        assertEquals(-1, clientCert.getBasicConstraints(), "Un certificat client ne doit pas être une CA (isCA=false)");
    }

    @Test
    @DisplayName("Test 3 : Émission à partir d'une demande CSR (PKCS#10)")
    void testIssueFromCsr() throws Exception {
        // 1. Génération d'une paire de clés pour le client externe
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048, new SecureRandom());
        KeyPair clientKeyPair = kpg.generateKeyPair();

        // 2. Création d'une CSR PKCS#10 valide
        X500Name subject = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.CN, "csr.serveur.local")
                .addRDN(BCStyle.O, "ENSET Mohammedia")
                .addRDN(BCStyle.C, "MA")
                .build();

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(clientKeyPair.getPrivate());

        PKCS10CertificationRequest csr = new JcaPKCS10CertificationRequestBuilder(subject, clientKeyPair.getPublic())
                .build(signer);

        String csrPem = PemUtils.toPem(csr);

        // 3. Soumission de la CSR à la PKI
        IssueCsrRequest csrRequest = new IssueCsrRequest();
        csrRequest.setCsrPem(csrPem);
        csrRequest.setType(CertificateType.SERVER);
        csrRequest.setValidityDays(180);
        csrRequest.setSubjectAlternativeNames("localhost, 127.0.0.1");

        CertificateEntity certEntity = certificateIssuingService.issueCertificateFromCsr(csrRequest);
        assertNotNull(certEntity);
        assertEquals("csr.serveur.local", certEntity.getCommonName());
        assertNull(certEntity.getPrivateKeyPem(), "La clé privée ne doit pas être stockée par la CA lors d'une signature CSR");

        // Vérification signature Root CA
        X509Certificate issuedCert = PemUtils.readCertificateFromPem(certEntity.getCertificatePem());
        assertDoesNotThrow(() -> issuedCert.verify(caService.getCaCertificate().getPublicKey()));
    }

    @Test
    @DisplayName("Test 4 : Révocation d'un certificat et émission de la CRL X.509 v2")
    void testRevokeCertificateAndCrl() throws Exception {
        // 1. Émettre un certificat
        IssueCertificateRequest req = new IssueCertificateRequest();
        req.setCommonName("compromised.client.ma");
        req.setType(CertificateType.CLIENT);
        CertificateEntity cert = certificateIssuingService.issueCertificate(req);

        // 2. Vérifier qu'il est actif initialement
        ValidationResult beforeRevoke = validationService.validateCertificate(cert.getCertificatePem());
        assertTrue(beforeRevoke.isValid(), "Le certificat doit être valide avant révocation");
        assertTrue(beforeRevoke.isNotRevoked(), "Le certificat ne doit pas être révoqué");

        // 3. Révoquer le certificat pour cause de compromission de clé
        RevokeCertificateRequest revokeReq = new RevokeCertificateRequest(
                cert.getSerialNumber(),
                RevocationReason.KEY_COMPROMISE,
                "Test compromission de clé"
        );
        CertificateEntity revokedCert = crlService.revokeCertificate(revokeReq);
        assertEquals(CertificateStatus.REVOKED, revokedCert.getStatus());

        // 4. Vérifier la CRL générée
        X509CRL crl = crlService.getX509Crl();
        assertNotNull(crl, "La CRL ne doit pas être nulle");
        assertDoesNotThrow(() -> crl.verify(caService.getCaCertificate().getPublicKey()), "La signature de la CRL doit être authentifiée par la Root CA");

        // 5. Valider avec le ValidationService (doit détecter la révocation dans la CRL)
        ValidationResult afterRevoke = validationService.validateCertificate(cert.getCertificatePem());
        assertFalse(afterRevoke.isValid(), "Le certificat révoqué ne doit plus être valide");
        assertFalse(afterRevoke.isNotRevoked(), "Le validateur doit indiquer que le certificat est révoqué");
        assertEquals(CertificateStatus.REVOKED, afterRevoke.getStatus());
        assertNotNull(afterRevoke.getRevocationReason(), "Le motif de révocation doit être renseigné");
    }
}
