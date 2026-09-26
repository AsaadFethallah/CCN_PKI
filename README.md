# CCN_PKI : Infrastructure à Clés Publiques (PKI) - Option B (MVP)

> **Projet Réalisé dans le cadre du module :** *Confiance Numérique et Accès Biométrique*  
> **Établissement :** École Normale Supérieure de l'Enseignement Technique (ENSET) Mohammedia  
> **Université :** Université Hassan II de Casablanca  
> **Option choisie :** **Option B — Développement d'un MVP PKI**  
> **Technologies :** Java 21, Spring Boot 3.3.5, Bouncy Castle 1.79, Thymeleaf, Docker & Docker Compose, OpenSSL 3.x

---

## Table des Matières

1. [Contexte et Objectifs](#1-contexte-et-objectifs)
2. [Architecture Générale du Système](#2-architecture-générale-du-système)
3. [Conformité aux Standards X.509 et RFC 5280](#3-conformité-aux-standards-x509-et-rfc-5280)
4. [Déploiement et Démarrage Rapide](#4-déploiement-et-démarrage-rapide)
   - [Option A : Déploiement Docker (Recommandé)](#option-a--déploiement-avec-docker--docker-compose)
   - [Option B : Exécution Locale (Maven Wrapper)](#option-b--exécution-locale-sans-docker)
5. [Démonstration des Fonctionnalités Clés](#5-démonstration-des-fonctionnalités-clés)
   - [1. Initialisation de la Root CA](#1-initialisation-de-la-root-ca-auto-signée)
   - [2. Émission d'un Certificat Client / Serveur](#2-émission-dun-certificat-client--serveur)
   - [3. Signature d'une Demande CSR (PKCS#10)](#3-signature-dune-demande-csr-pkcs10)
   - [4. Révocation et Émission de la CRL v2](#4-révocation-de-certificat-et-émission-de-la-crl-v2)
   - [5. Moteur de Validation Cryptographique](#5-moteur-de-validation-cryptographique-interne)
   - [6. Vérification Externe avec OpenSSL](#6-vérification-externe-avec-openssl-cli)
6. [Référentiel des API REST](#6-référentiel-des-api-rest)
7. [Analyse Critique (Forces, Limites et Perspectives)](#7-analyse-critique-forces-limites-et-perspectives)

---

## 1. Contexte et Objectifs

L'objectif de ce projet est de concevoir et implémenter une **Infrastructure à Clés Publiques (Public Key Infrastructure - PKI)** minimale mais pleinement fonctionnelle (MVP), capable de gérer l'intégralité du cycle de vie des certificats numériques selon les spécifications strictes de la **RFC 5280**.

### Exigences du Cahier des Charges (Option B) :
- [x] **Génération d'une biclé et certificat auto-signé (Root CA)** : Création d'une autorité racine de confiance avec paire de clés RSA 4096 bits.
- [x] **Signature de certificats clients et serveurs** : Émission de certificats X.509 v3 signés par la Root CA avec extensions obligatoires et SANs.
- [x] **Gestion des demandes CSR (PKCS#10)** : Vérification de la preuve de possession et signature sans connaissance de la clé privée cliente.
- [x] **Émission d'une liste de révocation (CRL X.509 v2)** : Révocation par numéro de série avec motifs standardisés RFC 5280.
- [x] **Mécanisme de validation** :
  - **Interne** : Moteur de vérification cryptographique (temporalité, signature Root CA, consultation CRL).
  - **Externe** : Compatibilité certifiée et testée avec **OpenSSL CLI** (`openssl verify -crl_check`).
- [x] **Conteneurisation Docker** : Déploiement clé en main via `Dockerfile` multi-stage et `docker-compose.yml`.

---

## 2. Architecture Générale du Système

Le système est structuré selon une architecture modulaire en couches, garantissant une séparation nette entre la logique cryptographique, la persistance et les interfaces d'interaction :

```
                                  +---------------------------------------+
                                  |         UTILISATEURS & CLIENTS        |
                                  +---------------------------------------+
                                         |                         |
                           (Web UI / Navigateur)          (API REST / cURL / OpenSSL)
                                         v                         v
+-----------------------------------------------------------------------------------+
|                            CCN_PKI - Spring Boot Application                      |
|                                                                                   |
|  [Contrôleurs]                                                                    |
|    ├── PkiWebController   : Interface utilisateur moderne Thymeleaf               |
|    └── PkiRestController  : Points d'accès RESTful JSON / PEM / DER               |
|                                                                                   |
|  [Services Métier]                                                                |
|    ├── CaService                 : Cycle de vie de la Root CA (RSA 4096)          |
|    ├── CertificateIssuingService : Émission X.509v3 directe & signature CSR       |
|    ├── CrlService                : Publication de la CRL X.509v2 signée           |
|    ├── ValidationService         : Moteur de contrôle RFC 5280                    |
|    └── OpenSslVerificationService: Validation externe via binaire OpenSSL         |
|                                                                                   |
|  [Moteur Cryptographique]                                                         |
|    └── Bouncy Castle Provider (bcprov-jdk18on & bcpkix-jdk18on v1.79)             |
|                                                                                   |
|  [Persistance & Stockage]                                                         |
|    ├── H2 Database (JPA) : Métadonnées, statuts, historique CRL et révocations    |
|    └── File Storage      : Clés PEM/DER, rootCA.crt, client.crt, crl.pem          |
+-----------------------------------------------------------------------------------+
```

### Organisation des Fichiers Source :
- `com.ccn.pki.CcnPkiApplication` : Point d'entrée avec enregistrement du fournisseur Bouncy Castle.
- `com.ccn.pki.service.CaService` : Création et persistance de la Root CA.
- `com.ccn.pki.service.CertificateIssuingService` : Logique d'émission et application des extensions X.509 v3.
- `com.ccn.pki.service.CrlService` : Construction et signature de la CRL X.509 v2.
- `com.ccn.pki.service.ValidationService` : Vérification cryptographique et logique de conformité.
- `com.ccn.pki.util.PemUtils` : Fonctions utilitaires de sérialisation PEM, DER et conteneurs PKCS#12.

---

## 3. Conformité aux Standards X.509 et RFC 5280

Pour assurer une compatibilité totale avec les systèmes d'exploitation, navigateurs et outils de sécurité (OpenSSL, cURL), les extensions suivantes sont injectées :

| Certificat | Extension X.509 v3 | OID | Valeur / Rôle | Criticité |
| :--- | :--- | :--- | :--- | :--- |
| **Root CA** | `BasicConstraints` | 2.5.29.19 | `cA=TRUE` (Définit l'autorité racine) | **Critique** |
| **Root CA** | `KeyUsage` | 2.5.29.15 | `keyCertSign`, `cRLSign`, `digitalSignature` | **Critique** |
| **Root CA** | `SubjectKeyIdentifier` | 2.5.29.14 | Hash SHA-1 de la clé publique de la CA | Non critique |
| **Root CA** | `AuthorityKeyIdentifier` | 2.5.29.35 | Identifiant de l'autorité (auto-référence) | Non critique |
| **Client / Serveur** | `BasicConstraints` | 2.5.29.19 | `cA=FALSE` (Entité finale / End-Entity) | **Critique** |
| **Client / Serveur** | `KeyUsage` | 2.5.29.15 | `digitalSignature`, `keyEncipherment` | **Critique** |
| **Client / Serveur** | `ExtendedKeyUsage` | 2.5.29.37 | `serverAuth`, `clientAuth`, `emailProtection` | Non critique |
| **Client / Serveur** | `CRLDistributionPoints` | 2.5.29.31 | `URI: http://localhost:8080/api/pki/crl/download` | Non critique |
| **Client / Serveur** | `SubjectAltName (SAN)` | 2.5.29.17 | Noms DNS et adresses IP (ex: `localhost`, `127.0.0.1`) | Non critique |
| **CRL v2** | `CRLNumber` | 2.5.29.20 | Numéro séquentiel incrémental de la version CRL | Non critique |
| **CRL v2** | `AuthorityKeyIdentifier` | 2.5.29.35 | Empreinte de la clé publique de la Root CA émettrice | Non critique |

---

## 4. Déploiement et Démarrage Rapide

### Option A : Déploiement avec Docker & Docker Compose (Recommandé)

L'application dispose d'un `Dockerfile` multi-stage basé sur **Temurin Java 21 Alpine** incluant **OpenSSL** pré-installé :

```bash
# 1. Cloner ou se placer dans le répertoire du projet
cd CCN_PKI

# 2. Lancer la construction et le démarrage du conteneur
docker compose up --build -d

# 3. Consulter les journaux en direct
docker compose logs -f
```

Une fois démarré, accédez à l'application :
- **Interface Web Dashboard :** [http://localhost:8080](http://localhost:8080)
- **Console H2 Database :** [http://localhost:8080/h2-console](http://localhost:8080/h2-console) (JDBC URL: `jdbc:h2:file:/app/pki-data/db/pkidb`)

Pour arrêter le conteneur :
```bash
docker compose down
```

---

### Option B : Exécution Locale (sans Docker)

Si vous disposez d'un JDK 21 sur votre machine :

```bash
# Sous Windows PowerShell :
.\mvnw.cmd spring-boot:run

# Sous Linux / macOS :
chmod +x mvnw
./mvnw spring-boot:run
```

Pour exécuter la suite de tests unitaires automatisés :
```bash
.\mvnw.cmd test
```

---

## 5. Démonstration des Fonctionnalités Clés

### 1. Initialisation de la Root CA Auto-Signée
Au démarrage, CCN_PKI initialise automatiquement une autorité racine par défaut :
- **Subject DN :** `CN=CCN Root CA, OU=Laboratoire Securite, O=ENSET Mohammedia, C=MA`
- **Taille de clé :** RSA 4096 bits
- **Durée :** 10 ans
- **Fichiers exportables :** `rootCA.crt` (PEM/DER), `rootCA.key` (Clé privée protégée).

Vous pouvez à tout moment régénérer une nouvelle CA depuis le menu **Root CA** de l'interface web.

---

### 2. Émission d'un Certificat Client / Serveur
Via l'interface Web (`/issue`) ou via l'API REST :

```bash
curl -X POST http://localhost:8080/api/pki/certificates/issue \
  -H "Content-Type: application/json" \
  -d '{
    "commonName": "etudiant.enset.ma",
    "organization": "ENSET Mohammedia",
    "organizationalUnit": "CyberSec",
    "country": "MA",
    "email": "etudiant@enset-media.ac.ma",
    "type": "CLIENT",
    "validityDays": 365,
    "keySize": 2048,
    "subjectAlternativeNames": "localhost, 127.0.0.1"
  }'
```

**Artefacts générés instantanément :**
- `serial.crt` : Certificat X.509 v3 signé par la Root CA.
- `serial.key` : Clé privée RSA du client au format PKCS#8 PEM.
- `serial.p12` : Trousseau PKCS#12 complet (clé + certificat + chaîne CA) importable dans un navigateur web ou un client email.

---

### 3. Signature d'une Demande CSR (PKCS#10)
Permet à un client de générer sa propre clé en local et de faire signer sa demande sans divulguer sa clé privée :

```bash
# Génération locale de la clé et de la CSR par le client :
openssl req -new -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/CN=serveur-interne.local/O=ENSET/C=MA"

# Soumission à l'API CCN_PKI :
curl -X POST http://localhost:8080/api/pki/certificates/issue-csr \
  -H "Content-Type: application/json" \
  -d '{
    "csrPem": "-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----",
    "type": "SERVER",
    "validityDays": 365
  }'
```

---

### 4. Révocation de Certificat et Émission de la CRL v2
Si une clé privée est compromise, le certificat est révoqué avec l'un des motifs standardisés de la RFC 5280 :
- `KEY_COMPROMISE` (Compromission de clé)
- `CA_COMPROMISE` (Compromission de la CA)
- `AFFILIATION_CHANGED` (Changement d'affectation)
- `SUPERSEDED` (Remplacé)
- `CESSATION_OF_OPERATION` (Cessation d'activité)
- `CERTIFICATE_HOLD` (Suspension temporaire)

```bash
curl -X POST http://localhost:8080/api/pki/certificates/revoke \
  -H "Content-Type: application/json" \
  -d '{
    "serialNumber": "VOTRE_NUMERO_DE_SERIE_HEX",
    "reason": "KEY_COMPROMISE",
    "comments": "Clé privée divulguée"
  }'
```

Dès la révocation :
1. Le statut passe à `REVOKED`.
2. Une nouvelle CRL X.509 v2 est générée, incrémentée (`CRLNumber`) et signée par la Root CA.
3. La CRL est immédiatement téléchargeable sur `http://localhost:8080/api/pki/crl/download`.

---

### 5. Moteur de Validation Cryptographique Interne
L'onglet **Validateur** (`/validate`) permet d'uploader un certificat pour tester en un clic :
- **Validité temporelle** : `notBefore <= date_courante <= notAfter`.
- **Intégrité & Signature** : Vérification mathématique par rapport à la clé publique de la Root CA (`cert.verify(caPublicKey)`).
- **Contrôle CRL** : Recherche du numéro de série dans la liste de révocation actuelle.

---

### 6. Vérification Externe avec OpenSSL CLI

La conformité avec OpenSSL a été vérifiée avec succès :

#### A. Vérification de la chaîne de confiance (Certificat Actif) :
```bash
openssl verify -CAfile pki-data/ca/rootCA.pem pki-data/certs/NUMERO_SERIE.crt
```
**Résultat OpenSSL :**
```text
pki-data/certs/NUMERO_SERIE.crt: OK
```

#### B. Vérification avec contrôle de révocation (-crl_check) :
```bash
openssl verify -CAfile pki-data/ca/rootCA.pem -CRLfile pki-data/crl/crl.pem -crl_check pki-data/certs/NUMERO_SERIE.crt
```

- **Si le certificat est Actif :**
  ```text
  pki-data/certs/NUMERO_SERIE.crt: OK
  ```
- **Si le certificat est Révoqué :**
  ```text
  CN=etudiant.enset.ma, O=ENSET Mohammedia, C=MA
  error 23 at 0 depth lookup: certificate revoked
  error pki-data/certs/NUMERO_SERIE.crt: verification failed
  ```

#### C. Inspection du Certificat et de la CRL :
```bash
# Lire le contenu d'un certificat émis :
openssl x509 -in pki-data/certs/NUMERO_SERIE.crt -text -noout

# Lire le contenu de la CRL signée :
openssl crl -in pki-data/crl/crl.pem -text -noout
```

---

## 6. Référentiel des API REST

| Méthode | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/pki/status` | Statistiques globales, état de la CA et de la CRL |
| `POST` | `/api/pki/ca/init` | Initialiser ou régénérer la Root CA auto-signée |
| `GET` | `/api/pki/ca/cert?format=pem\|der` | Télécharger le certificat de la Root CA |
| `POST` | `/api/pki/certificates/issue` | Émettre un certificat (génération directe de clé) |
| `POST` | `/api/pki/certificates/issue-csr` | Signer une demande de certificat CSR (PKCS#10) |
| `GET` | `/api/pki/certificates` | Liste complète de tous les certificats émis |
| `GET` | `/api/pki/certificates/{serial}` | Détails d'un certificat spécifique |
| `GET` | `/api/pki/certificates/{serial}/cert` | Télécharger le certificat (.crt) |
| `GET` | `/api/pki/certificates/{serial}/key` | Télécharger la clé privée (.key) |
| `GET` | `/api/pki/certificates/{serial}/p12` | Télécharger le trousseau PKCS#12 (.p12) |
| `POST` | `/api/pki/certificates/revoke` | Révoquer un certificat avec motif RFC 5280 |
| `GET` | `/api/pki/crl/download?format=pem\|der` | Télécharger la CRL active (Point de distribution) |
| `POST` | `/api/pki/crl/generate` | Forcer la régénération et signature de la CRL |
| `POST` | `/api/pki/certificates/validate` | Soumettre un certificat PEM pour validation complète |
| `GET` | `/api/pki/openssl/verify/{serial}` | Exécuter la commande OpenSSL en direct sur le serveur |

---

## 7. Analyse Critique (Forces, Limites et Perspectives)

Conformément aux consignes du TP de l'ENSET, voici l'analyse critique de l'implémentation :

### Points Forts :
1. **Conformité stricte RFC 5280** : Gestion rigoureuse des extensions X.509 v3 (`BasicConstraints`, `KeyUsage`, `ExtendedKeyUsage`, `SubjectKeyIdentifier`, `AuthorityKeyIdentifier`, `CRLDistributionPoints`, `SAN`).
2. **Double mode d'émission** : Supporte à la fois la génération clé-en-main côté serveur et le respect strict du secret de clé via le protocole CSR (PKCS#10).
3. **Double niveau de validation** : Moteur de contrôle applicatif Java natif + vérification externe standardisée via OpenSSL CLI.
4. **Portabilité et Déploiement** : Image Docker Alpine légère avec OpenSSL intégré et persistance de données sur volumes.
5. **Ergonomie** : Interface web interactive avec mode sombre moderne, visualiseur d'empreintes SHA-256 et téléchargements en un clic.

### Limites Actuelles :
1. **Architecture mono-niveau** : Le MVP utilise une Root CA unique. En environnement d'entreprise, une Root CA hors-ligne (Offline Root CA) délègue la signature à une ou plusieurs autorités subordonnées (Intermediate / Issuing CAs).
2. **Absence du protocole OCSP (RFC 6960)** : La validation repose sur les listes CRL, ce qui nécessite le téléchargement périodique de toute la liste plutôt qu'une interrogation granulaire en ligne par requête OCSP.
3. **Stockage logiciel des clés privées** : Les clés privées sont stockées sous forme chiffrée/fichier plutôt que dans un module de sécurité matériel (HSM - Hardware Security Module).

### Perspectives d'Évolution :
- Implémentation d'un répondeur OCSP (Online Certificate Status Protocol) pour des vérifications légères en temps réel.
- Prise en charge du protocole ACME (RFC 8555) pour l'automatisation du renouvellement des certificats (type Let's Encrypt).
- Gestion d'une hiérarchie complète à 2 niveaux (Root CA & Intermediate CA).
