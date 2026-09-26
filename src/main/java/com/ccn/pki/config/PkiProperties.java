package com.ccn.pki.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Propriétés de configuration de la PKI CCN_PKI
 */
@Configuration
@ConfigurationProperties(prefix = "pki")
public class PkiProperties {

    private Storage storage = new Storage();
    private Ca ca = new Ca();
    private Cert cert = new Cert();
    private Crl crl = new Crl();

    public static class Storage {
        private String baseDir = "./pki-data";

        public String getBaseDir() {
            return baseDir;
        }

        public void setBaseDir(String baseDir) {
            this.baseDir = baseDir;
        }

        public Path getCaDir() {
            return Paths.get(baseDir, "ca");
        }

        public Path getCertsDir() {
            return Paths.get(baseDir, "certs");
        }

        public Path getKeysDir() {
            return Paths.get(baseDir, "keys");
        }

        public Path getCrlDir() {
            return Paths.get(baseDir, "crl");
        }
    }

    public static class Ca {
        private String defaultDn = "CN=CCN Root CA, OU=Laboratoire Sécurité, O=ENSET Mohammedia, C=MA";
        private int validityYears = 10;
        private int keySize = 4096;

        public String getDefaultDn() {
            return defaultDn;
        }

        public void setDefaultDn(String defaultDn) {
            this.defaultDn = defaultDn;
        }

        public int getValidityYears() {
            return validityYears;
        }

        public void setValidityYears(int validityYears) {
            this.validityYears = validityYears;
        }

        public int getKeySize() {
            return keySize;
        }

        public void setKeySize(int keySize) {
            this.keySize = keySize;
        }
    }

    public static class Cert {
        private int defaultValidityDays = 365;

        public int getDefaultValidityDays() {
            return defaultValidityDays;
        }

        public void setDefaultValidityDays(int defaultValidityDays) {
            this.defaultValidityDays = defaultValidityDays;
        }
    }

    public static class Crl {
        private int validityDays = 30;
        private String distributionPoint = "http://localhost:8080/api/pki/crl/download";

        public int getValidityDays() {
            return validityDays;
        }

        public void setValidityDays(int validityDays) {
            this.validityDays = validityDays;
        }

        public String getDistributionPoint() {
            return distributionPoint;
        }

        public void setDistributionPoint(String distributionPoint) {
            this.distributionPoint = distributionPoint;
        }
    }

    public Storage getStorage() {
        return storage;
    }

    public void setStorage(Storage storage) {
        this.storage = storage;
    }

    public Ca getCa() {
        return ca;
    }

    public void setCa(Ca ca) {
        this.ca = ca;
    }

    public Cert getCert() {
        return cert;
    }

    public void setCert(Cert cert) {
        this.cert = cert;
    }

    public Crl getCrl() {
        return crl;
    }

    public void setCrl(Crl crl) {
        this.crl = crl;
    }
}
