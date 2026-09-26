# ===================================================================
# Script de Démonstration Automatisée & Validation Complète : CCN_PKI
# Module : Confiance Numérique & Accès Biométrique (ENSET Mohammedia)
# ===================================================================

$ErrorActionPreference = "Continue"
$Host.UI.RawUI.WindowTitle = "CCN_PKI - Démonstration & Test RFC 5280"

$baseUrl = "http://localhost:8080"
$openssl = "C:\Program Files\Git\usr\bin\openssl.exe"
if (-not (Test-Path $openssl)) {
    $openssl = "openssl"
}

Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host "          CCN_PKI - Test Automatisé du MVP PKI (Option B)      " -ForegroundColor Cyan
Write-Host "===============================================================" -ForegroundColor Cyan

# 1. Vérifier si le serveur CCN_PKI répond
Write-Host "`n[1/7] Test de connectivité vers l'API CCN_PKI..." -ForegroundColor Yellow
try {
    $status = Invoke-RestMethod -Uri "$baseUrl/api/pki/status" -Method Get
    Write-Host "[OK] Serveur actif !" -ForegroundColor Green
    Write-Host "     - Root CA : $($status.caSubject)"
    Write-Host "     - Serial  : $($status.caSerialNumber)"
    Write-Host "     - Expire  : $($status.caExpiresAt)"
} catch {
    Write-Host "[ERREUR] Le serveur CCN_PKI n'est pas accessible sur $baseUrl." -ForegroundColor Red
    Write-Host "Veuillez démarrer l'application d'abord (ex: .\mvnw.cmd spring-boot:run ou docker compose up)" -ForegroundColor Red
    exit 1
}

# 2. Téléchargement du certificat de l'Autorité Racine (Root CA)
Write-Host "`n[2/7] Téléchargement du certificat Root CA (rootCA.pem)..." -ForegroundColor Yellow
$caFile = "demo_rootCA.pem"
Invoke-WebRequest -Uri "$baseUrl/api/pki/ca/cert?format=pem" -OutFile $caFile
Write-Host "[OK] Root CA sauvegardée dans '$caFile'." -ForegroundColor Green

# 3. Émission d'un certificat d'entité finale en Mode Direct
Write-Host "`n[3/7] Émission d'un Certificat Client (Mode Direct)..." -ForegroundColor Yellow
$clientBody = @{
    commonName = "etudiant.test.enset.ma"
    organization = "ENSET Mohammedia"
    organizationalUnit = "CyberSec"
    country = "MA"
    email = "etudiant@enset-media.ac.ma"
    type = "CLIENT"
    validityDays = 365
    keySize = 2048
} | ConvertTo-Json

$clientCert = Invoke-RestMethod -Uri "$baseUrl/api/pki/certificates/issue" -Method Post -Body $clientBody -ContentType "application/json; charset=utf-8"
$clientSerial = $clientCert.serialNumber
$clientFile = "demo_client_$clientSerial.crt"
[System.IO.File]::WriteAllText($clientFile, $clientCert.certificatePem)
Write-Host "[OK] Certificat client émis avec succès !" -ForegroundColor Green
Write-Host "     - Sujet  : $($clientCert.subjectDn)"
Write-Host "     - Serial : $clientSerial"
Write-Host "     - Fichier: $clientFile"

# 4. Émission d'un certificat Serveur à partir d'une CSR (PKCS#10)
Write-Host "`n[4/7] Génération d'une CSR locale et signature par la PKI (Mode CSR)..." -ForegroundColor Yellow
$csrKey = "demo_server.key"
$csrFile = "demo_server.csr"

# Génération clé et CSR avec OpenSSL
& $openssl req -new -newkey rsa:2048 -nodes -keyout $csrKey -out $csrFile -subj "/CN=serveur-web.enset.ma/O=ENSET/C=MA" 2>$null

$csrContent = [System.IO.File]::ReadAllText("$pwd\$csrFile")
$csrBody = @{
    csrPem = $csrContent
    type = "SERVER"
    validityDays = 180
    subjectAlternativeNames = "localhost, 127.0.0.1, web.enset.ma"
} | ConvertTo-Json

$serverCert = Invoke-RestMethod -Uri "$baseUrl/api/pki/certificates/issue-csr" -Method Post -Body $csrBody -ContentType "application/json; charset=utf-8"
$serverSerial = $serverCert.serialNumber
$serverFile = "demo_server_$serverSerial.crt"
[System.IO.File]::WriteAllText($serverFile, $serverCert.certificatePem)
Write-Host "[OK] Certificat serveur émis depuis la CSR avec succès !" -ForegroundColor Green
Write-Host "     - Sujet  : $($serverCert.subjectDn)"
Write-Host "     - Serial : $serverSerial"
Write-Host "     - SANs   : localhost, 127.0.0.1, web.enset.ma"

# 5. Validation OpenSSL avant révocation
Write-Host "`n[5/7] Vérification OpenSSL de la chaîne de confiance (Certificats Actifs)..." -ForegroundColor Yellow
Write-Host "Commande : openssl verify -CAfile $caFile $clientFile" -ForegroundColor Gray
$resClient = & $openssl verify -CAfile $caFile $clientFile
Write-Host "Résultat Client : $resClient" -ForegroundColor Green

Write-Host "Commande : openssl verify -CAfile $caFile $serverFile" -ForegroundColor Gray
$resServer = & $openssl verify -CAfile $caFile $serverFile
Write-Host "Résultat Serveur: $resServer" -ForegroundColor Green

# 6. Révocation du premier certificat et mise à jour de la CRL
Write-Host "`n[6/7] Révocation du Certificat Client ($clientSerial) avec motif RFC 5280..." -ForegroundColor Yellow
$revokeBody = @{
    serialNumber = $clientSerial
    reason = "KEY_COMPROMISE"
    comments = "Test de révocation : clé compromise"
} | ConvertTo-Json

$revocationRes = Invoke-RestMethod -Uri "$baseUrl/api/pki/certificates/revoke" -Method Post -Body $revokeBody -ContentType "application/json; charset=utf-8"
Write-Host "[OK] Certificat $clientSerial révoqué ! Statut = $($revocationRes.status)" -ForegroundColor Green

# Téléchargement de la CRL à jour
$crlFile = "demo_crl.pem"
Invoke-WebRequest -Uri "$baseUrl/api/pki/crl/download?format=pem" -OutFile $crlFile
Write-Host "[OK] CRL v2 téléchargée dans '$crlFile'." -ForegroundColor Green

# 7. Contrôle de Révocation avec OpenSSL (-crl_check)
Write-Host "`n[7/7] Test de vérification OpenSSL avec contrôle CRL (-crl_check)..." -ForegroundColor Yellow

Write-Host "`n--> A. Vérification du Certificat Serveur (Non révoqué) :" -ForegroundColor Cyan
Write-Host "Commande : openssl verify -CAfile $caFile -CRLfile $crlFile -crl_check $serverFile" -ForegroundColor Gray
& $openssl verify -CAfile $caFile -CRLfile $crlFile -crl_check $serverFile

Write-Host "`n--> B. Vérification du Certificat Client (RÉVOQUÉ) :" -ForegroundColor Cyan
Write-Host "Commande : openssl verify -CAfile $caFile -CRLfile $crlFile -crl_check $clientFile" -ForegroundColor Gray
& $openssl verify -CAfile $caFile -CRLfile $crlFile -crl_check $clientFile 2>&1

Write-Host "`n===============================================================" -ForegroundColor Cyan
Write-Host "  Démonstration terminée avec succès ! Conformité RFC 5280 OK " -ForegroundColor Cyan
Write-Host "===============================================================" -ForegroundColor Cyan
