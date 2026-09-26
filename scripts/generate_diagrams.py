import os
import plantuml

os.makedirs('images', exist_ok=True)
server = plantuml.PlantUML(url='http://www.plantuml.com/plantuml/img/')

# ==============================================================================
# 1. DIAGRAMME USE CASE (Cas d'Utilisation)
# ==============================================================================
puml_usecase = """@startuml
skinparam dpi 220
skinparam defaultFontName "Segoe UI", Helvetica, Arial, sans-serif
skinparam defaultFontSize 11
skinparam shadowing false
skinparam roundcorner 8

skinparam actor {
    BackgroundColor #E2E8F0
    BorderColor #102C57
    FontColor #102C57
    FontSize 12
    FontStyle bold
}

skinparam usecase {
    BackgroundColor #F8FAFC
    BorderColor #1450A0
    FontColor #0F172A
    BorderThickness 1.2
    ArrowColor #1450A0
    ArrowThickness 1.2
}

left to right direction

actor "Administrateur Securite\\n(Laboratoire Securite)" as Admin
actor "Utilisateur / Candidat\\n(Etudiant / Serveur)" as User
actor "Moteur d'Audit Externe\\n(OpenSSL CLI)" as Auditor

rectangle "Systeme CCN_PKI (Infrastructure a Cles Publiques)" as PKISystem #F8FAFC {

    package "1. Gestion Autorite Racine (Root CA)" #FFFFFF {
        usecase "UC1: Initialiser / Consulter Root CA\\n(Bicle RSA 4096, Extensions cA=TRUE)" as UC1
        usecase "UC2: Exporter Certificat Racine\\n(rootCA.crt au format PEM/DER)" as UC2
    }

    package "2. Emission de Certificats X.509 v3" #FFFFFF {
        usecase "UC3: Emettre Certificat Direct\\n(Bicle RSA 2048 + Trousseau PKCS#12)" as UC3
        usecase "UC4: Soumettre Demande CSR (PKCS#10)" as UC4
        usecase "UC5: Signer CSR & Verifier\\nPreuve de Possession (PoP)" as UC5
        usecase "UC6: Telecharger Certificat (.crt),\\nCle Privee (.key) ou PKCS#12 (.p12)" as UC6
    }

    package "3. Cycle de Revocation (RFC 5280)" #FFFFFF {
        usecase "UC7: Revoquer Certificat\\n(Motif RFC 5280: keyCompromise...)" as UC7
        usecase "UC8: Forger & Signer la CRL v2\\n(Incr. CRLNumber, AuthKeyId)" as UC8
        usecase "UC9: Publier / Telecharger la CRL\\n(Point de distribution HTTP /crl)" as UC9
    }

    package "4. Audit, Validation & Supervision" #FFFFFF {
        usecase "UC10: Valider Certificat en Ligne\\n(Audit 4 Niveaux: Syntaxe, Dates, Signature, CRL)" as UC10
        usecase "UC11: Audit Conforme OpenSSL CLI\\n(openssl verify -crl_check)" as UC11
        usecase "UC12: Consulter Dashboard Metriques\\n(Statistiques CA, Certs, Requetes)" as UC12
    }
}

' Relations Acteurs -> Use Cases
Admin --> UC1
Admin --> UC7
Admin --> UC8
Admin --> UC11
Admin --> UC12

User --> UC2
User --> UC3
User --> UC4
User --> UC6
User --> UC9
User --> UC10

Auditor --> UC2
Auditor --> UC9
Auditor --> UC11

' Inclusions et Extensions
UC7 ..> UC8 : <<include>>
UC4 <.. UC5 : <<include>>
UC3 ..> UC6 : <<extend>>
UC10 ..> UC9 : <<include>>
UC11 ..> UC2 : <<include>>
UC11 ..> UC9 : <<include>>

@enduml"""

# ==============================================================================
# 2. DIAGRAMME DE SÉQUENCE (Flux Scénario Complet)
# ==============================================================================
puml_sequence = """@startuml
skinparam dpi 220
skinparam defaultFontName "Segoe UI", Helvetica, Arial, sans-serif
skinparam defaultFontSize 11
skinparam shadowing false
skinparam roundcorner 8

skinparam sequence {
    ArrowColor #1450A0
    ArrowThickness 1.5
    LifeLineBorderColor #102C57
    LifeLineBackgroundColor #E2E8F0
    ParticipantBorderColor #102C57
    ParticipantBackgroundColor #F8FAFC
    ParticipantFontColor #102C57
    ParticipantFontStyle bold
    BoxBackgroundColor #F1F5F9
    BoxBorderColor #CBD5E1
}

autonumber "<b>[00]</b>"

actor "Utilisateur\\n(Yassine)" as User
actor "Administrateur\\n(Securite)" as Admin
boundary "IHM Web / REST\\n(PkiController)" as Web
control "Service Emission\\n(CertificateIssuingService)" as IssueSvc
control "Service CA\\n(CaService)" as CaSvc
control "Service CRL\\n(CrlService)" as CrlSvc
control "Moteur Validation\\n(ValidationService)" as ValSvc
database "Persistance\\n(H2 DB & pki-data/)" as DB
entity "Binaire Externe\\n(OpenSSL CLI)" as OpenSSL

== Phase 1 : Emission Securisee via CSR (PKCS#10) ==

User -> User : Generation locale bicle RSA 2048\\net confection CSR (client.csr)
User -> Web : POST /api/pki/certificates/issue-csr (csrPem, profile, san)
activate Web
Web -> IssueSvc : issueCertificateFromCsr(csrDto)
activate IssueSvc

IssueSvc -> IssueSvc : Verifier la signature interne de la CSR\\n(Preuve de Possession cryptographique)
IssueSvc -> CaSvc : getCaCertificateHolder() & getCaPrivateKey()
activate CaSvc
CaSvc --> IssueSvc : caCertHolder, caPrivateKey
deactivate CaSvc

IssueSvc -> IssueSvc : Forger X509v3 (Serial 64-bit, SAN, CDP, EKU)\\net signer avec caPrivateKey
IssueSvc -> DB : save(CertificateEntity) & ecrire yassine.crt
activate DB
DB --> IssueSvc : confirmation persistance
deactivate DB

IssueSvc --> Web : Certificat X.509 v3 emis
Web --> User : Fichier PEM yassine.crt disponible
deactivate IssueSvc
deactivate Web

== Phase 2 : Verification Nominale (Acces Autorise) ==

User -> Web : POST /validate (certificat yassine.crt)
activate Web
Web -> ValSvc : validateCertificatePem(pem)
activate ValSvc

ValSvc -> ValSvc : 1. Controle syntaxe ASN.1\\n2. Controle dates [notBefore, notAfter]
ValSvc -> CaSvc : getCaCertificate() -> verifier signature RSA
activate CaSvc
CaSvc --> ValSvc : caCert
deactivate CaSvc

ValSvc -> CrlSvc : getLatestCrlHolder() -> verifier serial absent
activate CrlSvc
CrlSvc --> ValSvc : crlHolder (liste vide de Yassine)
deactivate CrlSvc

ValSvc --> Web : ValidationResult(VALID = true)
deactivate ValSvc
Web --> User : Badge Vert : "CERTIFICAT VALIDE"
deactivate Web

== Phase 3 : Declaration d'Incident & Revocation ==

User -> Admin : Signalement : "Cle USB egaree / compromission cle privee"
Admin -> Web : POST /certificates/revoke (serial, reason=keyCompromise)
activate Web
Web -> CrlSvc : revokeCertificate(serial, reasonCode=1)
activate CrlSvc

CrlSvc -> DB : update CertificateEntity set revoked=true, reasonCode=1
activate DB
DB --> CrlSvc : OK
deactivate DB

CrlSvc -> CaSvc : getCaPrivateKey()
activate CaSvc
CaSvc --> CrlSvc : caPrivateKey
deactivate CaSvc

CrlSvc -> CrlSvc : Construire X509v2CRLBuilder\\nIncr. CRLNumber (#2)\\nSigner CRL avec caPrivateKey
CrlSvc -> DB : save(CrlEntity) & ecrire crl.pem, crl.crl
activate DB
DB --> CrlSvc : OK
deactivate DB

CrlSvc --> Web : CRL mise a jour
deactivate CrlSvc
Web --> Admin : Confirmation : Certificat revoque & CRL publiee
deactivate Web

== Phase 4 : Tentative d'Acces Bloquee & Audit OpenSSL ==

User -> Web : POST /validate (certificat yassine.crt apres incident)
activate Web
Web -> ValSvc : validateCertificatePem(pem)
activate ValSvc
ValSvc -> CrlSvc : getLatestCrlHolder()
activate CrlSvc
CrlSvc --> ValSvc : crlHolder (contient serial de Yassine)
deactivate CrlSvc
ValSvc --> Web : ValidationResult(VALID = false, REVOKED = true, reason=keyCompromise)
deactivate ValSvc
Web --> User : Alerte Rouge : "ACCES REFUSE - CERTIFICAT REVOQUE"
deactivate Web

Admin -> Web : Executer Audit OpenSSL (/openssl-guide)
activate Web
Web -> OpenSSL : openssl verify -CAfile rootCA.pem -CRLfile crl.pem -crl_check yassine.crt
activate OpenSSL
OpenSSL --> Web : "error 23 at 0 depth lookup: certificate revoked"
deactivate OpenSSL
Web --> Admin : Preuve formelle d'audit OpenSSL (Erreur 23 confirmee)
deactivate Web

@enduml"""

# ==============================================================================
# 3. DIAGRAMME DE CLASSES (Modèle de Domaine & Services)
# ==============================================================================
puml_classes = """@startuml
skinparam dpi 220
skinparam defaultFontName "Segoe UI", Helvetica, Arial, sans-serif
skinparam defaultFontSize 11
skinparam shadowing false
skinparam roundcorner 6

skinparam class {
    BackgroundColor #FFFFFF
    BorderColor #102C57
    HeaderBackgroundColor #102C57
    FontColor #0F172A
    HeaderFontColor #FFFFFF
    FontSize 11
    BorderThickness 1.2
}

skinparam package {
    BackgroundColor #F8FAFC
    BorderColor #CBD5E1
    FontColor #102C57
    FontStyle bold
}

package "com.ccn.pki.model (Entites Persistantes JPA & DTOs)" {
    class CaEntity <<Entity>> {
        - Long id
        - String subjectDn
        - String issuerDn
        - String serialNumberHex
        - String certificatePem
        - String privateKeyEncryptedPem
        - String publicKeyPem
        - Date notBefore
        - Date notAfter
        - boolean active
    }

    class CertificateEntity <<Entity>> {
        - Long id
        - String subjectDn
        - String issuerDn
        - String serialNumberHex
        - String certificatePem
        - String privateKeyEncryptedPem
        - String publicKeyPem
        - String profile
        - String sanList
        - boolean revoked
        - Integer revocationReasonCode
        - Date revokedAt
        - Date issuedAt
        - Date notBefore
        - Date notAfter
        - boolean csrBased
    }

    class CrlEntity <<Entity>> {
        - Long id
        - Long crlNumber
        - String issuerDn
        - Date thisUpdate
        - Date nextUpdate
        - String crlPem
        - String crlDerBase64
        - int revokedCount
        - boolean active
    }

    class ValidationResult <<DTO>> {
        - boolean valid
        - boolean revoked
        - String subjectDn
        - String issuerDn
        - String serialNumberHex
        - Date notBefore
        - Date notAfter
        - String details
        - String revocationReason
        - Date revocationDate
        + {static} valid(...) : ValidationResult
        + {static} revoked(...) : ValidationResult
        + {static} invalid(...) : ValidationResult
    }
}

package "com.ccn.pki.service (Logique Metier & Cryptographie)" {
    class CaService {
        - CaRepository caRepository
        - Path caStoragePath
        + initRootCa(subjectDn, validityYears) : X509Certificate
        + getCaCertificate() : X509Certificate
        + getCaPrivateKey() : PrivateKey
        + getCaCertificateHolder() : X509CertificateHolder
        + isCaInitialized() : boolean
        - saveCaFiles(cert, keyPair) : void
    }

    class CertificateIssuingService {
        - CertificateRepository certRepository
        - CaService caService
        - Path certStoragePath
        + issueDirectCertificate(issueDto) : CertificateEntity
        + issueCertificateFromCsr(csrDto) : CertificateEntity
        + generatePkcs12(serialHex, password) : byte[]
        + getCertificateEntity(serialHex) : CertificateEntity
    }

    class CrlService {
        - RevocationRepository crlRepository
        - CertificateRepository certRepository
        - CaService caService
        - Path crlStoragePath
        + generateAndPublishCrl() : X509CRLHolder
        + revokeCertificate(serialHex, reasonCode) : void
        + getLatestCrlHolder() : X509CRLHolder
        + getCrlPem() : String
        + getCrlDer() : byte[]
    }

    class ValidationService {
        - CaService caService
        - CrlService crlService
        + validateCertificatePem(certPem) : ValidationResult
        + validateCertificate(x509Cert) : ValidationResult
    }

    class OpenSslVerificationService {
        + verifyCertificate(certFile, caFile, crlFile) : String
        + runOpenSslCommand(commandArgs) : String
    }
}

package "com.ccn.pki.controller (Couche Web MVC & REST)" {
    class PkiRestController {
        - CaService caService
        - CertificateIssuingService issueService
        - CrlService crlService
        - ValidationService validationService
        + getStatus() : ResponseEntity
        + initCa(dto) : ResponseEntity
        + getCaCert(format) : ResponseEntity
        + issueCertificate(dto) : ResponseEntity
        + issueCsr(dto) : ResponseEntity
        + listCertificates() : List
        + revokeCertificate(dto) : ResponseEntity
        + downloadCrl(format) : ResponseEntity
        + validateCertificate(dto) : ResponseEntity
    }

    class PkiWebController {
        - CaService caService
        - CertificateIssuingService issueService
        - CrlService crlService
        - ValidationService validationService
        - OpenSslVerificationService openSslService
        + dashboard(model) : String
        + caPage(model) : String
        + issuePage(model) : String
        + certificatesPage(model) : String
        + crlPage(model) : String
        + validatePage(model) : String
        + openSslGuidePage(model) : String
    }
}

package "com.ccn.pki.util (ASN.1 & Encodages Bouncy Castle)" {
    class PemUtils {
        + {static} readCertificateFromPem(pemStr) : X509Certificate
        + {static} readPrivateKeyFromPem(pemStr) : PrivateKey
        + {static} toPem(obj) : String
        + {static} calculateSha256Thumbprint(cert) : String
        + {static} createPkcs12(alias, cert, key, password) : byte[]
    }
}

' Relations Logiques
CaService --> CaEntity : persiste
CertificateIssuingService --> CertificateEntity : persiste
CertificateIssuingService --> CaService : utilise pour signer
CrlService --> CrlEntity : persiste
CrlService --> CaService : utilise pour signer CRL
CrlService --> CertificateEntity : met a jour

ValidationService --> CaService : verifie signature
ValidationService --> CrlService : controle revocation
ValidationService ..> ValidationResult : instancie

PkiRestController --> CaService
PkiRestController --> CertificateIssuingService
PkiRestController --> CrlService
PkiRestController --> ValidationService

PkiWebController --> CaService
PkiWebController --> CertificateIssuingService
PkiWebController --> CrlService
PkiWebController --> ValidationService
PkiWebController --> OpenSslVerificationService

CaService ..> PemUtils : serialise
CertificateIssuingService ..> PemUtils : convertit
ValidationService ..> PemUtils : decode

@enduml"""

# ==============================================================================
# 4. ARCHITECTURE TECHNIQUE DÉTAILLÉE (Couches & Conteneur Docker)
# ==============================================================================
puml_arch = """@startuml
skinparam dpi 220
skinparam defaultFontName "Segoe UI", Helvetica, Arial, sans-serif
skinparam defaultFontSize 11
skinparam shadowing false
skinparam roundcorner 8

skinparam rectangle {
    BackgroundColor #FFFFFF
    BorderColor #102C57
    FontColor #0F172A
    BorderThickness 1.5
}

skinparam node {
    BackgroundColor #F8FAFC
    BorderColor #1450A0
    FontColor #102C57
    FontStyle bold
}

skinparam database {
    BackgroundColor #FEF3C7
    BorderColor #D97706
    FontColor #78350F
    FontStyle bold
}

top to bottom direction

package "1. Clients Externes & Environnement Utilisateur" #F1F5F9 {
    actor "Administrateur / Etudiant\\n(Navigateur Web)" as Browser #E2E8F0
    component "Client REST / CLI\\n(cURL, Python, Postman)" as RestClient #E2E8F0
    component "Outil d'Audit Standardise\\n(OpenSSL 3.x CLI)" as OpenSslTool #E2E8F0
}

package "2. Machine Hote & Plateforme de Conteneurisation" #E2E8F0 {
    
    portin "Port 8080 (HTTP / REST)" as HostPort

    node "Conteneur Docker : ccn-pki-app\\n(Alpine Linux 3.20 + Eclipse Temurin JRE 21 LTS)" #FFFFFF {
        
        package "Couche Presentation (UI & Routage MVC)" #EEF2F6 {
            component "Thymeleaf Template Engine\\n(Dashboard, CA, Issue, CRL, OpenSSL)" as Thymeleaf
            component "PkiWebController\\n(Spring MVC Routing)" as WebCtrl
            component "PkiRestController\\n(/api/pki/* JSON & PEM Endpoints)" as RestCtrl
        }

        package "Couche Logique Metier & Services PKI" #E0E7FF {
            component "CaService\\n(Gestion Root CA RSA 4096)" as SvcCA
            component "CertificateIssuingService\\n(Direct & CSR PKCS#10)" as SvcIssue
            component "CrlService\\n(Revocation RFC 5280 & CRL v2)" as SvcCRL
            component "ValidationService\\n(Moteur d'Audit 4 Niveaux)" as SvcVal
            component "OpenSslVerificationService\\n(Execution Wrapper ProcessBuilder)" as SvcOpenSSL
        }

        package "Moteur Cryptographique & Outils Systeme" #FEF2F2 {
            component "Bouncy Castle APIs (v1.79)\\n- bcprov-jdk18on (RSA, SHA-256)\\n- bcpkix-jdk18on (X509v3, CSR, CRL)" as BouncyCastle #FEE2E2
            component "PemUtils (ASN.1, Empreintes, PKCS#12)" as Utils #FEE2E2
            component "Binaire Systeme OpenSSL 3.3.x\\n(/usr/bin/openssl)" as SysOpenSsl #F3F4F6
        }

        package "Couche Acces aux Donnees (Data Layer)" #ECFDF5 {
            component "Spring Data JPA / Hibernate 6\\n(CaRepository, CertificateRepository, RevocationRepository)" as DataJPA
        }
    }

    node "3. Stockage Persistant (Volume Monte : ./pki-data)" #FFFBEB {
        database "Base de Donnees H2 (Fichier MV)\\n./pki-data/db/pkidb.mv.db\\n(Tables: CA_ENTITY, CERTIFICATES, CRL)" as H2DB
        
        folder "Stockage Fichiers Cryptographiques (pki-data/)" as FileSystem {
            file "pki-data/ca/\\nrootCA.crt, rootCA.key" as F_CA
            file "pki-data/certs/\\n*.crt, *.key, *.p12" as F_Certs
            file "pki-data/crl/\\ncrl.pem, crl.crl" as F_CRL
        }
    }
}

' Flux Clients -> Port Hote
Browser --> HostPort
RestClient --> HostPort
OpenSslTool --> HostPort

' Routage Port Hote -> Controleurs
HostPort --> WebCtrl
HostPort --> RestCtrl

' MVC interne
WebCtrl --> Thymeleaf
WebCtrl --> SvcCA
WebCtrl --> SvcIssue
WebCtrl --> SvcCRL
WebCtrl --> SvcVal
WebCtrl --> SvcOpenSSL

RestCtrl --> SvcCA
RestCtrl --> SvcIssue
RestCtrl --> SvcCRL
RestCtrl --> SvcVal

' Services -> Cryptographie Bouncy Castle & OpenSSL
SvcCA --> BouncyCastle
SvcIssue --> BouncyCastle
SvcCRL --> BouncyCastle
SvcVal --> BouncyCastle
SvcCA ..> Utils
SvcIssue ..> Utils
SvcOpenSSL --> SysOpenSsl : execute via ProcessBuilder

' Services -> Persistance JPA
SvcCA --> DataJPA
SvcIssue --> DataJPA
SvcCRL --> DataJPA
DataJPA --> H2DB

' Services -> Fichiers Disque
SvcCA --> F_CA : enregistre
SvcIssue --> F_Certs : exporte
SvcCRL --> F_CRL : publie

@enduml"""

diagrams = [
    ("images/diagramme_use_case.png", puml_usecase),
    ("images/diagramme_sequence.png", puml_sequence),
    ("images/diagramme_classes.png", puml_classes),
    ("images/architecture_technique.png", puml_arch),
]

for filename, code in diagrams:
    print(f"Generating {filename}...")
    png_data = server.processes(code)
    with open(filename, 'wb') as f:
        f.write(png_data)
    print(f"-> Successfully written {filename} ({len(png_data)} bytes)")

print("\nALL 4 DIAGRAMS SUCCESSFULLY REGENERATED WITHOUT WARNINGS!")
