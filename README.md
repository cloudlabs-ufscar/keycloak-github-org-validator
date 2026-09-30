# Keycloak GitHub Organization Authenticator

[![Keycloak](https://img.shields.io/badge/Keycloak-25+-blue.svg)](https://www.keycloak.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)

A flexible, lightweight, and modern **Keycloak 25+ (Quarkus / Jakarta EE)** Authenticator SPI that:
1. **Enforces GitHub Organization Membership:** Blocks authentication if the user does not belong to at least one of the configured GitHub organizations.
2. **Supports Multiple Organizations:** Define a comma-separated list of allowed organizations.
3. **Optional Local Password Enforcement:** Seamlessly prompts first-time federated users to create a local password credential (`UPDATE_PASSWORD`), enabling autonomous offline access for CLIs and local logins.
4. **Resilient API Strategy:** Combines bulk checks (`/user/orgs`) with individual membership fallbacks (`/orgs/{org}/members/{user}`).

---

## 🎯 Features

* **Multi-Org Filtering:** Supports one or multiple GitHub organizations (e.g., `cloudlabs-ufscar, other-org`).
* **First Broker Login Integration:** Acts as an admission gatekeeper before any user record is persisted in Keycloak's database.
* **Autonomous Local Passwords (Optional):** Injects Keycloak's native `UPDATE_PASSWORD` required action so users can subsequently log in using username & password without touching GitHub.
* **Custom Error Messages:** Tailor the rejection message shown to unauthorized users with dynamic `{user}` and `{orgs}` placeholders.
* **Modern Stack:** Built for Keycloak 25+ using Java 17, `jakarta.*` packages, and Quarkus-native provider loading.

---

## 🛠️ Build & Installation

### Requirements
* **Java 17+**
* **Apache Maven 3.8+**

### Compile
```bash
mvn clean package
```

The resulting JAR file will be located at:
```text
target/keycloak-github-org-validator.jar
```

### Install in Keycloak
1. Copy the `.jar` to Keycloak's `providers/` directory:
   * **Bare-metal / Container:** `/opt/keycloak/providers/keycloak-github-org-validator.jar`
   * **In Docker Compose:** Mount it into `/opt/keycloak/providers/`
2. Restart Keycloak.

---

## ⚙️ Configuration in Keycloak Admin Console

### 1. Configure the Identity Provider
* Go to **Identity Providers** ➔ **github**.
* Ensure the **Default Scopes** field contains:
  ```text
  openid user:email read:org
  ```

### 2. Configure the Authentication Flow
1. Go to **Authentication** ➔ **Flows**.
2. Duplicate the built-in **`first broker login`** flow and name it (e.g., `cloudlabs-first-broker-login`).
3. Click **Add step** / **Add execution** and select:
   * **`GitHub Organization Validator`**
4. Set its requirement to **`REQUIRED`** and position it at the **top** of the flow.
5. Click on the ⚙️ gear icon next to the execution to configure:
   * **Organizações Permitidas:** `cloudlabs-ufscar, lab-secundario`
   * **Exigir Criação de Senha Local:** `true` (or `false`)
   * **Mensagem de Erro Customizada:** *(Optional)* `Acesso restrito: você precisa ser membro de {orgs} para acessar.`
6. Return to **Identity Providers** ➔ **github** and set **First Login Flow** to your newly created flow.

---

## 📄 License
Apache License 2.0. Developed for the CloudLabs UFSCar project and the open-source community.
