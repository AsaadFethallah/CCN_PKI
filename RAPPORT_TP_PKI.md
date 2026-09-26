# RAPPORT DE TRAVAUX PRATIQUES
## Module : Confiance Numérique et Accès Biométrique
### TP : Conception d’une Infrastructure à Clés Publiques (PKI)
#### Option 2 — Développement d’un MVP PKI : "CCN_PKI"

---

**Établissement :** École Normale Supérieure de l'Enseignement Technique de Mohammedia (ENSET)  
**Université :** Université Hassan II de Casablanca  
**Année Universitaire :** 2025 – 2026  
**Auteurs (Groupe) :**
- Étudiant 1
- Étudiant 2
- Étudiant 3
- Étudiant 4  

---

## 1. Contexte, Objectifs et Choix de Conception du MVP

### 1.1 Contexte Théorique et Justification du Choix
Dans les architectures de sécurité modernes, l'Infrastructure à Clés Publiques (**PKI** - *Public Key Infrastructure*) constitue le socle fondamental de la confiance numérique. Elle résout la problématique de la distribution sécurisée des clés publiques en liant de manière cryptographique et infalsifiable l'identité d'une entité (personne physique, service, machine) à une clé publique au travers d'un **certificat numérique X.509**, garanti par une **Autorité de Certification (CA)**.

Plutôt que d'analyser une solution open source préexistante (Option 1), notre groupe a fait le choix délibéré de **l'Option 2 (Développement d'un MVP PKI)**. Ce choix présente une valeur pédagogique supérieure car il impose de :
- Manipuler directement les structures de données ASN.1 et primitives cryptographiques ;
- Maîtriser le chaînage de confiance et les extensions X.509 v3 normalisées par la **RFC 5280** ;
- Implémenter le mécanisme d'authentification et de révocation via les **Listes de Révocation de Certificats (CRL X.509 v2)** ;
- Développer une double approche de validation : applicative native et interopérable avec l'outil de référence mondial **OpenSSL**.

### 1.2 Spécifications et Objectifs Atteints par CCN_PKI
Le projet **CCN_PKI** remplit l'intégralité du cahier des charges et intègre plusieurs enrichissements valorisants :
1. **Autorité Racine (Root CA) minimale et robuste** : Génération d'une biclé RSA 4096 bits et d'un certificat auto-signé avec extensions critiques `BasicConstraints` et `KeyUsage`.
2. **Émission multi-modes de certificats d'entité finale** :
   - *Mode Direct* : Génération de la biclé et du certificat côté autorité avec téléchargement du trousseau complet **PKCS#12 (.p12)**.
   - *Mode CSR (PKCS#10)* : Traitement d'une demande de signature avec vérification de la preuve de possession (*Proof of Possession*) garantissant que la clé privée ne quitte jamais le client.
3. **Publication et mise à jour dynamique de la CRL (RFC 5280)** : Révocation par numéro de série avec spécification de la cause standardisée (`keyCompromise`, etc.) et mise à jour de la CRL v2 signée.
4. **Moteur de validation complet (Bonus optionnel)** :
   - Interface Web interactive d'analyse X.509.
   - Script et commandes de vérification automatisée via **OpenSSL CLI** (`openssl verify -crl_check`).
5. **Déploiement industriel par conteneurisation (Docker)** : `Dockerfile` multi-stage basé sur Alpine Linux avec OpenSSL et JDK 21 intégrés.

---

## 2. Description de l’Architecture et du Code

### 2.1 Choix Technologiques
- **Langage & Framework :** Java 21 LTS & Spring Boot 3.3.5 (architecture robuste, typage fort, injection de dépendances).
- **Moteur Cryptographique :** **Bouncy Castle 1.79** (`bcprov-jdk18on` et `bcpkix-jdk18on`). Bouncy Castle est le standard industriel sous Java pour les opérations ASN.1, PKCS et X.509.
- **Interface Utilisateur :** Thymeleaf 3, HTML5 sémantique et CSS Vanilla personnalisé (palette sombre Cyber-Security).
- **Persistance :** Spring Data JPA couplé au moteur relationnel H2 persistant sur disque (`pki-data/db/pkidb`).
- **Conteneurisation :** Docker Engine & Docker Compose.

### 2.2 Diagramme d'Architecture Applicative

```
+-----------------------------------------------------------------------------------+
|                            INTERFACES UTILISATEUR & API                           |
|      [Navigateur Web / UI Thymeleaf]            [Client REST / Scripts CLI / cURL]|
+-----------------------------------------------------------------------------------+
                                         │
                                         ▼
+-----------------------------------------------------------------------------------+
|                            COUCHE CONTRÔLEURS SPRING                              |
|   • PkiWebController   : Vues Dashboard, CA, Émission, Inventaire, CRL, Validateur|
|   • PkiRestController  : Points d'accès RESTful (/api/pki/*)                      |
+-----------------------------------------------------------------------------------+
                                         │
                                         ▼
+-----------------------------------------------------------------------------------+
|                            COUCHE SERVICES MÉTIER (PKI)                           |
|   • CaService                 : Initialisation, auto-signature, cycle de vie CA   |
|   • CertificateIssuingService : Émission X.509v3, CSR PKCS#10, injection SAN      |
|   • CrlService                : Signature X.509v2 CRL, ajout motifs RFC 5280      |
|   • ValidationService         : Moteur de contrôle temporel, signature et CRL     |
|   • OpenSslVerificationService: Wrapper d'exécution et reporting OpenSSL CLI     |
+-----------------------------------------------------------------------------------+
                                         │
                                         ▼
+-----------------------------------------------------------------------------------+
|                       FOURNISSEUR CRYPTOGRAPHIQUE BOUNCY CASTLE                   |
|   • JcaX509v3CertificateBuilder, JcaX509v2CRLBuilder, JcaContentSignerBuilder     |
+-----------------------------------------------------------------------------------+
                                         │
                                         ▼
+-----------------------------------------------------------------------------------+
|                               PERSISTANCE DES DONNÉES                             |
|   • Base Relationnelle (H2 JPA) : Métadonnées, historiques et états de révocation |
|   • Système de Fichiers         : ./pki-data/{ca, certs, keys, crl}               |
+-----------------------------------------------------------------------------------+
```

### 2.3 Détail des Composants Clés du Code

#### A. Initialisation et Auto-Signature de la Root CA (`CaService.java`)
La Root CA est l'ancre de confiance (*Trust Anchor*). Pour être reconnue valide par les validateurs conformes à la RFC 5280 :
- L'émetteur (*Issuer*) doit être rigoureusement identique au sujet (*Subject*).
- L'extension **BasicConstraints** doit obligatoirement avoir le fanion `cA=TRUE` avec statut **critique**.
- L'extension **KeyUsage** doit autoriser explicitement `keyCertSign` et `cRLSign`.

```java
// Construction du certificat auto-signé X.509 v3
X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
        issuer, serialNumber, notBefore, notAfter, subject, caKeyPair.getPublic()
);

// Basic Constraints (Critique) : indique formellement qu'il s'agit d'une autorité
certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

// Key Usage (Critique) : autorisation de signer des certificats et des CRL
certBuilder.addExtension(Extension.keyUsage, true,
        new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.digitalSignature));

// Signature avec l'algorithme sécurisé SHA256withRSA
ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
        .setProvider("BC").build(caKeyPair.getPrivate());
```

#### B. Signature des Certificats Clients & Serveurs (`CertificateIssuingService.java`)
Lors de la signature d'un certificat d'entité finale :
- L'extension `BasicConstraints` est fixée à `cA=FALSE` (critique), empêchant un attaquant d'utiliser sa clé client pour usurper le rôle d'une CA.
- L'extension `CRLDistributionPoints` est injectée pour spécifier aux clients où interroger la liste de révocation.
- Les **Subject Alternative Names (SAN)** sont ajoutés pour permettre l'authentification moderne SSL/TLS dans les navigateurs et clients web.
- L'`Issuer` est extrait de la CA via `new JcaX509CertificateHolder(caCert).getSubject()`, assurant une correspondance binaire exacte de l'encodage DER de l'autorité.

#### C. Gestion de la Liste de Révocation (`CrlService.java`)
Lorsqu'un certificat est révoqué :
1. Son entrée est consignée en base avec le code de motif RFC 5280 (`CRLReason`).
2. Le constructeur `JcaX509v2CRLBuilder` ajoute chaque entrée révoquée avec la date et le motif.
3. L'extension `CRLNumber` est incrémentée à chaque publication pour permettre aux validateurs de détecter les nouvelles versions.
4. La CRL est signée par la clé privée de la Root CA et exportée aux formats PEM (`crl.pem`) et DER (`crl.crl`).

---

## 3. Démonstration de l’Émission de Certificats

La plateforme offre deux modes distincts d'émission :

### 3.1 Démonstration de l'Émission Directe (Client TLS)
- **Paramètres :**
  - Nom Commun (CN) : `etudiant.enset.ma`
  - Organisation (O) : `ENSET Mohammedia`
  - Unité (OU) : `CyberSec`
  - Pays (C) : `MA`
  - Type : `CLIENT`
  - Validité : 365 jours, Clé RSA 2048 bits
- **Artefacts produits instantanément :**
  - `AB28099296E0C67B.crt` : Certificat public X.509v3 signé.
  - `AB28099296E0C67B.key` : Clé privée RSA du client au format PKCS#8 PEM.
  - `AB28099296E0C67B.p12` : Trousseau chiffré PKCS#12 contenant la clé, le certificat et le certificat de la Root CA.

### 3.2 Démonstration de l'Émission via CSR (Serveur Web)
Cette approche respecte le principe de moindre privilège : le serveur génère sa propre biclé et ne communique que sa CSR :

```bash
# Génération de la clé et de la demande CSR côté serveur :
openssl req -new -newkey rsa:2048 -nodes \
    -keyout server.key -out server.csr \
    -subj "/CN=serveur.enset.ma/O=ENSET Mohammedia/C=MA"
```

La CSR est transmise à CCN_PKI (`/api/pki/certificates/issue-csr`). La PKI vérifie la signature interne de la CSR (*Proof of Possession*) avant de délivrer le certificat serveur signé par la Root CA.

---

## 4. Exemples de Vérification et de Validation

### 4.1 Vérification Applicative (Moteur Interne)
L'interface `/validate` permet de soumettre un certificat et applique les 4 contrôles séquentiels :

```
[OK] Format X.509 valide détecté et parsé avec succès.
[OK] Validité temporelle confirmée : valide du 25/09/2026 au 26/09/2027.
[OK] Signature cryptographique vérifiée avec succès avec la clé publique de la Root CA.
[OK] Contrôle CRL : Le certificat ne figure pas dans la liste de révocation.
--> STATUT GLOBAL : CERTIFICAT VALIDE ET DE CONFIANCE
```

### 4.2 Vérification Externe Certifiée avec OpenSSL CLI

#### Cas 1 : Certificat Actif et Valide
Exécution de la commande de vérification avec la chaîne de confiance et la CRL :
```bash
openssl verify -CAfile pki-data/ca/rootCA.pem -CRLfile pki-data/crl/crl.pem -crl_check pki-data/certs/AB28099296E0C67B.crt
```
**Sortie Console :**
```text
pki-data/certs/AB28099296E0C67B.crt: OK
```
*Interprétation :* La chaîne cryptographique est intègre, l'autorité racine est reconnue, et le certificat ne figure dans aucune entrée de la CRL.

#### Cas 2 : Certificat Révoqué pour Compromission de Clé
Révocation du certificat `AB28099296E0C67B` avec motif `KEY_COMPROMISE`.
Ré-exécution immédiate de la commande OpenSSL :
```bash
openssl verify -CAfile pki-data/ca/rootCA.pem -CRLfile pki-data/crl/crl.pem -crl_check pki-data/certs/AB28099296E0C67B.crt
```
**Sortie Console :**
```text
CN=etudiant.enset.ma, O=ENSET Mohammedia, OU=CyberSec, C=MA
error 23 at 0 depth lookup: certificate revoked
error pki-data/certs/AB28099296E0C67B.crt: verification failed
```
*Interprétation :* OpenSSL détecte immédiatement le numéro de série dans la nouvelle CRL signée et rejette le certificat avec l'erreur standard `certificate revoked (code 23)`.

#### Cas 3 : Inspection de la CRL X.509 v2
```bash
openssl crl -in pki-data/crl/crl.pem -text -noout
```
**Extrait du résultat :**
```text
Certificate Revocation List (CRL):
    Version 2 (0x1)
    Signature Algorithm: sha256WithRSAEncryption
    Issuer: CN=CCN Root CA, OU=Laboratoire Securite, O=ENSET Mohammedia, C=MA
    Last Update: Sep 26 13:19:54 2026 GMT
    Next Update: Oct 26 13:19:54 2026 GMT
    CRL extensions:
        X509v3 CRL Number: 2
        X509v3 Authority Key Identifier: ...
Revoked Certificates:
    Serial Number: AB28099296E0C67B
        Revocation Date: Sep 26 13:19:54 2026 GMT
        CRL entry extensions:
            X509v3 CRL Reason Code:
                Key Compromise
```

---

## 5. Analyse Critique (Forces, Limites et Améliorations)

### 5.1 Points Forts de la Solution
1. **Conformité stricte RFC 5280** : Gestion complète des extensions X.509 v3 et CRL v2 avec criticité conforme aux standards de l'IETF.
2. **Double mode d'interaction** : Interface graphique moderne Thymeleaf et API REST JSON/PEM facilitant l'automatisation par scripts.
3. **Double mode d'émission** : Prise en charge des CSR (PKCS#10) garantissant la confidentialité des clés privées clientes.
4. **Déploiement Docker optimisé** : Image conteneurisée Alpine multi-stage autonome incluant OpenSSL pour des tests instantanés.
5. **Persistance robuste** : Base de données H2 couplée à une synchronisation automatique sur disque des fichiers de clés et certificats.

### 5.2 Limites Identifiées du MVP
1. **Architecture PKI à un seul niveau** : Le MVP emploie une Root CA unique. En production réelle, la Root CA est conservée hors-ligne (*Offline Root CA*) et délègue l'émission quotidienne à une ou plusieurs Autorités Subordonnées (*Issuing / Intermediate CAs*).
2. **Absence du protocole OCSP (RFC 6960)** : La vérification de révocation repose exclusivement sur les listes CRL. Si le nombre de certificats révoqués croît considérablement, le téléchargement de la CRL devient lourd pour la bande passante.
3. **Sécurité logicielle des clés** : Les clés privées de l'autorité sont stockées sur le système de fichiers hôte, sans protection par un module cryptographique matériel dédié (**HSM** - *Hardware Security Module*).

### 5.3 Perspectives et Pistes d'Évolution
- **Mise en place d'un répondeur OCSP** : Fournir un endpoint `/api/pki/ocsp` permettant une validation granulaire temps réel par requête unitaire.
- **Support du protocole ACME (RFC 8555)** : Automatiser la délivrance et le renouvellement de certificats serveurs à la manière de Let's Encrypt.
- **Hiérarchie à 2 niveaux** : Séparation fonctionnelle entre Root CA (auto-signée, durée 15 ans) et Intermediate CA (signée par la racine, durée 3 ans).

---

## 6. Guide d'Exécution et de Reproduction

### Déploiement Docker :
```bash
cd CCN_PKI
docker compose up --build -d
```
Accès Web : `http://localhost:8080`

### Exécution du Script de Démonstration Automatisée :
```powershell
.\test-pki-flow.ps1
```
Le script exécute en séquence l'ensemble du cycle de vie PKI et affiche les résultats colorés avec OpenSSL.

### Exécution des Tests Automatisés Maven :
```powershell
$env:JAVA_HOME = "C:\Program Files\JetBrains\IntelliJ IDEA 2025.3\jbr"
.\mvnw.cmd test
```
*Succès : 4/4 tests validés (Root CA, Client, CSR, CRL).*
