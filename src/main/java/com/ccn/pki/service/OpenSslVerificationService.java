package com.ccn.pki.service;

import com.ccn.pki.config.PkiProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * ===================================================================
 * Service d'Intégration et Validation Externe via OpenSSL
 * ===================================================================
 * Permet de tester la compatibilité et conformité des certificats et de
 * la CRL émis par CCN_PKI avec l'outil standard OpenSSL CLI.
 */
@Service
public class OpenSslVerificationService {

    private static final Logger log = LoggerFactory.getLogger(OpenSslVerificationService.class);

    private final PkiProperties pkiProperties;

    public OpenSslVerificationService(PkiProperties pkiProperties) {
        this.pkiProperties = pkiProperties;
    }

    /**
     * Tente de localiser le binaire openssl sur le système hôte
     */
    public String findOpenSslBinary() {
        // 1. Tester openssl dans le PATH standard
        try {
            Process p = new ProcessBuilder("openssl", "version").start();
            if (p.waitFor() == 0) {
                return "openssl";
            }
        } catch (Exception ignored) {
        }

        // 2. Emplacement typique Git for Windows
        String gitOpenSsl = "C:\\Program Files\\Git\\usr\\bin\\openssl.exe";
        if (new File(gitOpenSsl).exists()) {
            return gitOpenSsl;
        }

        return "openssl";
    }

    /**
     * Exécute la vérification OpenSSL sur un certificat donné
     *
     * @param certSerialNumber Numéro de série du certificat à vérifier
     * @param checkCrl          Si true, vérifie également la révocation via la CRL
     * @return Rapport de commande et sortie d'exécution
     */
    public OpenSslRunResult runOpenSslVerify(String certSerialNumber, boolean checkCrl) {
        OpenSslRunResult result = new OpenSslRunResult();
        try {
            Path caFile = pkiProperties.getStorage().getCaDir().resolve("rootCA.pem").toAbsolutePath();
            Path certFile = pkiProperties.getStorage().getCertsDir().resolve(certSerialNumber + ".crt").toAbsolutePath();
            Path crlFile = pkiProperties.getStorage().getCrlDir().resolve("crl.pem").toAbsolutePath();

            if (!Files.exists(caFile)) {
                result.setSuccess(false);
                result.setOutput("Erreur : Le fichier de l'Autorité Racine (" + caFile + ") n'existe pas.");
                return result;
            }

            if (!Files.exists(certFile)) {
                result.setSuccess(false);
                result.setOutput("Erreur : Le fichier du certificat client (" + certFile + ") n'existe pas.");
                return result;
            }

            String opensslBin = findOpenSslBinary();
            List<String> command = new ArrayList<>();
            command.add(opensslBin);
            command.add("verify");
            command.add("-CAfile");
            command.add(caFile.toString());

            if (checkCrl && Files.exists(crlFile)) {
                command.add("-CRLfile");
                command.add(crlFile.toString());
                command.add("-crl_check");
            }

            command.add(certFile.toString());

            result.setExecutedCommand(String.join(" ", command));

            ProcessBuilder pb = new ProcessBuilder(command);
            pb.redirectErrorStream(true);
            Process process = pb.start();

            StringBuilder sb = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line).append("\n");
                }
            }

            int exitCode = process.waitFor();
            result.setExitCode(exitCode);
            result.setOutput(sb.toString().trim());
            result.setSuccess(exitCode == 0);

        } catch (Exception e) {
            log.error("Erreur lors de l'exécution OpenSSL : {}", e.getMessage());
            result.setSuccess(false);
            result.setOutput("Erreur d'exécution : " + e.getMessage());
        }

        return result;
    }

    public static class OpenSslRunResult {
        private String executedCommand;
        private int exitCode;
        private String output;
        private boolean success;

        public String getExecutedCommand() {
            return executedCommand;
        }

        public void setExecutedCommand(String executedCommand) {
            this.executedCommand = executedCommand;
        }

        public int getExitCode() {
            return exitCode;
        }

        public void setExitCode(int exitCode) {
            this.exitCode = exitCode;
        }

        public String getOutput() {
            return output;
        }

        public void setOutput(String output) {
            this.output = output;
        }

        public boolean isSuccess() {
            return success;
        }

        public void setSuccess(boolean success) {
            this.success = success;
        }
    }
}
