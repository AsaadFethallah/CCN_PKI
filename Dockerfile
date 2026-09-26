# ===================================================================
# Dockerfile Multi-Stage pour CCN_PKI
# Application Spring Boot PKI MVP (ENSET Mohammedia)
# ===================================================================

# -------------------------------------------------------------
# Étape 1 : Construction de l'application (Build Stage)
# -------------------------------------------------------------
FROM eclipse-temurin:21-jdk-alpine AS builder

WORKDIR /build

# Copie des fichiers de configuration Maven et du wrapper
COPY .mvn/ .mvn/
COPY mvnw pom.xml ./

# Rendre le script wrapper exécutable
RUN chmod +x ./mvnw

# Téléchargement et mise en cache des dépendances
RUN ./mvnw dependency:go-offline -B

# Copie des sources du projet
COPY src ./src

# Compilation et empaquetage du fichier JAR exécutable
RUN ./mvnw clean package -DskipTests

# -------------------------------------------------------------
# Étape 2 : Image d'Exécution Minimale & Sécurisée (Runtime Stage)
# -------------------------------------------------------------
FROM eclipse-temurin:21-jre-alpine

WORKDIR /app

# Installation d'OpenSSL et curl dans le conteneur
# Essentiel pour la validation externe et les tests OpenSSL requis par le TP
RUN apk add --no-cache openssl curl tzdata

# Configuration du fuseau horaire
ENV TZ=Africa/Casablanca

# Création du répertoire de persistance pour les certificats, clés et CRL
RUN mkdir -p /app/pki-data && chmod 777 /app/pki-data

# Copie du binaire JAR généré à l'étape précédente
COPY --from=builder /build/target/ccn-pki-*.jar app.jar

# Exposition du port Web HTTP de la PKI
EXPOSE 8080

# Déclaration du volume persistant
VOLUME ["/app/pki-data"]

# Démarrage de l'application Spring Boot
ENTRYPOINT ["java", "-Djava.security.egd=file:/dev/./urandom", "-jar", "app.jar"]
