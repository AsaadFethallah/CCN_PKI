package com.ccn.pki.controller;

import com.ccn.pki.dto.IssueCertificateRequest;
import com.ccn.pki.dto.IssueCsrRequest;
import com.ccn.pki.dto.RevokeCertificateRequest;
import com.ccn.pki.dto.ValidationResult;
import com.ccn.pki.model.CaEntity;
import com.ccn.pki.model.CertificateEntity;
import com.ccn.pki.model.CertificateStatus;
import com.ccn.pki.model.CertificateType;
import com.ccn.pki.model.RevocationReason;
import com.ccn.pki.repository.CertificateRepository;
import com.ccn.pki.repository.CrlRepository;
import com.ccn.pki.repository.RevocationRepository;
import com.ccn.pki.service.CaService;
import com.ccn.pki.service.CertificateIssuingService;
import com.ccn.pki.service.CrlService;
import com.ccn.pki.service.OpenSslVerificationService;
import com.ccn.pki.service.ValidationService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * ===================================================================
 * Contrôleur Web MVC (Thymeleaf) pour l'Interface Utilisateur
 * ===================================================================
 */
@Controller
public class PkiWebController {

    private final CaService caService;
    private final CertificateIssuingService certificateIssuingService;
    private final CrlService crlService;
    private final ValidationService validationService;
    private final OpenSslVerificationService openSslVerificationService;
    private final CertificateRepository certificateRepository;
    private final RevocationRepository revocationRepository;
    private final CrlRepository crlRepository;

    public PkiWebController(CaService caService,
                            CertificateIssuingService certificateIssuingService,
                            CrlService crlService,
                            ValidationService validationService,
                            OpenSslVerificationService openSslVerificationService,
                            CertificateRepository certificateRepository,
                            RevocationRepository revocationRepository,
                            CrlRepository crlRepository) {
        this.caService = caService;
        this.certificateIssuingService = certificateIssuingService;
        this.crlService = crlService;
        this.validationService = validationService;
        this.openSslVerificationService = openSslVerificationService;
        this.certificateRepository = certificateRepository;
        this.revocationRepository = revocationRepository;
        this.crlRepository = crlRepository;
    }

    /**
     * Page d'accueil / Tableau de bord
     */
    @GetMapping("/")
    public String dashboard(Model model) {
        model.addAttribute("activeNav", "dashboard");
        model.addAttribute("ca", caService.getActiveCa());
        model.addAttribute("totalCount", certificateRepository.count());
        model.addAttribute("activeCount", certificateRepository.countByStatus(CertificateStatus.ACTIVE));
        model.addAttribute("revokedCount", certificateRepository.countByStatus(CertificateStatus.REVOKED));
        model.addAttribute("expiredCount", certificateRepository.countByStatus(CertificateStatus.EXPIRED));
        model.addAttribute("latestCrl", crlRepository.findFirstByOrderByCrlNumberDesc().orElse(null));
        model.addAttribute("recentCerts", certificateRepository.findAllByOrderByIssuedAtDesc().stream().limit(5).toList());
        return "dashboard";
    }

    /**
     * Page de gestion de la Root CA
     */
    @GetMapping("/ca")
    public String caManagement(Model model) {
        model.addAttribute("activeNav", "ca");
        model.addAttribute("ca", caService.getActiveCa());
        return "ca";
    }

    /**
     * Action d'initialisation / régénération de la Root CA
     */
    @PostMapping("/ca/init")
    public String initRootCa(@RequestParam String subjectDn,
                             @RequestParam(defaultValue = "10") int validityYears,
                             @RequestParam(defaultValue = "4096") int keySize,
                             RedirectAttributes redirectAttributes) {
        try {
            caService.initializeRootCa(subjectDn, validityYears, keySize);
            crlService.generateAndPublishCrl();
            redirectAttributes.addFlashAttribute("successMessage", "Autorité Racine (Root CA) générée avec succès !");
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("errorMessage", "Erreur lors de la génération de la Root CA : " + e.getMessage());
        }
        return "redirect:/ca";
    }

    /**
     * Page d'émission de certificats
     */
    @GetMapping("/issue")
    public String issuePage(Model model) {
        model.addAttribute("activeNav", "issue");
        model.addAttribute("issueForm", new IssueCertificateRequest());
        model.addAttribute("csrForm", new IssueCsrRequest());
        model.addAttribute("types", CertificateType.values());
        return "issue";
    }

    /**
     * Action d'émission d'un certificat (Mode Direct)
     */
    @PostMapping("/issue/direct")
    public String handleDirectIssue(@ModelAttribute IssueCertificateRequest request,
                                    RedirectAttributes redirectAttributes) {
        try {
            CertificateEntity cert = certificateIssuingService.issueCertificate(request);
            redirectAttributes.addFlashAttribute("successMessage",
                    "Certificat émis avec succès pour '" + cert.getCommonName() + "' (Serial: " + cert.getSerialNumber() + ")");
            redirectAttributes.addFlashAttribute("issuedCert", cert);
            return "redirect:/issue?issued=" + cert.getSerialNumber();
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("errorMessage", "Erreur lors de l'émission : " + e.getMessage());
            return "redirect:/issue";
        }
    }

    /**
     * Action de signature d'une CSR (PKCS#10)
     */
    @PostMapping("/issue/csr")
    public String handleCsrIssue(@RequestParam(value = "csrFile", required = false) MultipartFile csrFile,
                                 @RequestParam(value = "csrPem", required = false) String csrPem,
                                 @RequestParam(defaultValue = "365") int validityDays,
                                 @RequestParam CertificateType type,
                                 @RequestParam(required = false) String subjectAlternativeNames,
                                 RedirectAttributes redirectAttributes) {
        try {
            String content = csrPem;
            if (csrFile != null && !csrFile.isEmpty()) {
                content = new String(csrFile.getBytes(), StandardCharsets.UTF_8);
            }

            if (content == null || content.trim().isEmpty()) {
                throw new IllegalArgumentException("Veuillez fournir le contenu d'une CSR valide (fichier ou texte).");
            }

            IssueCsrRequest request = new IssueCsrRequest();
            request.setCsrPem(content);
            request.setValidityDays(validityDays);
            request.setType(type);
            request.setSubjectAlternativeNames(subjectAlternativeNames);

            CertificateEntity cert = certificateIssuingService.issueCertificateFromCsr(request);
            redirectAttributes.addFlashAttribute("successMessage",
                    "Certificat émis à partir de la CSR avec succès pour '" + cert.getCommonName() + "' (Serial: " + cert.getSerialNumber() + ")");
            redirectAttributes.addFlashAttribute("issuedCert", cert);
            return "redirect:/issue?issued=" + cert.getSerialNumber();
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("errorMessage", "Erreur lors de la signature CSR : " + e.getMessage());
            return "redirect:/issue";
        }
    }

    /**
     * Page de liste et gestion des certificats
     */
    @GetMapping("/certificates")
    public String listCertificates(@RequestParam(required = false) CertificateStatus status,
                                   Model model) {
        model.addAttribute("activeNav", "certificates");
        List<CertificateEntity> certs;
        if (status != null) {
            certs = certificateRepository.findByStatus(status);
        } else {
            certs = certificateRepository.findAllByOrderByIssuedAtDesc();
        }
        model.addAttribute("certificates", certs);
        model.addAttribute("selectedStatus", status);
        model.addAttribute("reasons", RevocationReason.values());
        return "certificates";
    }

    /**
     * Action de révocation d'un certificat
     */
    @PostMapping("/certificates/revoke")
    public String revokeCertificate(@RequestParam String serialNumber,
                                    @RequestParam RevocationReason reason,
                                    @RequestParam(required = false) String comments,
                                    RedirectAttributes redirectAttributes) {
        try {
            RevokeCertificateRequest request = new RevokeCertificateRequest(serialNumber, reason, comments);
            crlService.revokeCertificate(request);
            redirectAttributes.addFlashAttribute("successMessage", "Le certificat " + serialNumber + " a été révoqué avec succès et ajouté à la CRL !");
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("errorMessage", "Erreur lors de la révocation : " + e.getMessage());
        }
        return "redirect:/certificates";
    }

    /**
     * Page de gestion de la CRL
     */
    @GetMapping("/crl")
    public String crlPage(Model model) {
        model.addAttribute("activeNav", "crl");
        model.addAttribute("latestCrl", crlRepository.findFirstByOrderByCrlNumberDesc().orElse(null));
        model.addAttribute("revocations", revocationRepository.findAllByOrderByRevocationDateDesc());
        return "crl";
    }

    /**
     * Action pour forcer la regénération de la CRL
     */
    @PostMapping("/crl/generate")
    public String regenerateCrl(RedirectAttributes redirectAttributes) {
        try {
            crlService.generateAndPublishCrl();
            redirectAttributes.addFlashAttribute("successMessage", "Liste de Révocation (CRL) regénérée et signée avec succès !");
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("errorMessage", "Erreur lors de la regénération de la CRL : " + e.getMessage());
        }
        return "redirect:/crl";
    }

    /**
     * Page de vérification et validation d'un certificat
     */
    @GetMapping("/validate")
    public String validatePage(Model model) {
        model.addAttribute("activeNav", "validate");
        return "validate";
    }

    /**
     * Action de vérification d'un certificat
     */
    @PostMapping("/validate")
    public String handleValidate(@RequestParam(value = "certFile", required = false) MultipartFile certFile,
                                 @RequestParam(value = "certPem", required = false) String certPem,
                                 Model model) {
        model.addAttribute("activeNav", "validate");
        try {
            String content = certPem;
            if (certFile != null && !certFile.isEmpty()) {
                content = new String(certFile.getBytes(), StandardCharsets.UTF_8);
            }

            ValidationResult result = validationService.validateCertificate(content);
            model.addAttribute("result", result);
            model.addAttribute("submittedPem", content);
        } catch (Exception e) {
            model.addAttribute("errorMessage", "Erreur lors du traitement du certificat : " + e.getMessage());
        }
        return "validate";
    }

    /**
     * Guide pas-à-pas et exécution OpenSSL
     */
    @GetMapping("/openssl-guide")
    public String opensslGuide(@RequestParam(required = false) String serialNumber,
                               @RequestParam(defaultValue = "false") boolean runCheck,
                               Model model) {
        model.addAttribute("activeNav", "openssl");
        model.addAttribute("certificates", certificateRepository.findAllByOrderByIssuedAtDesc());
        model.addAttribute("selectedSerial", serialNumber);

        if (serialNumber != null && runCheck) {
            var openSslResult = openSslVerificationService.runOpenSslVerify(serialNumber, true);
            model.addAttribute("openSslResult", openSslResult);
        }

        return "openssl-guide";
    }
}
