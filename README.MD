# Ory Kratos Authentication and Authorization

## 1. Introduction

## 2. Prerequisites

Ensure you have the following tools installed before proceeding:

-   **Docker**: To run the services in containers.
-   **Docker Compose**: To manage multi-container Docker applications.

You also need to configure an OAuth2 provider, like Google, if you wish to use OAuth login.

## 3. Configuration

There are four main files to configure:

-   **`docker-compose-kratos.yml`**: Defines the containers, including Ory Kratos, UI, MailSlurper, and migrations.
-   **`kratos.yml`**: The Kratos configuration file that defines the services, identity schemas, and email settings.
-   **`docker-compose-hydra.yml`**:
-   **`hydra.yml`**:

### docker-compose-kratos.yml Configuration

The `docker-compose-kratos.yml` file includes:

-   **Ory Kratos** for identity management
-   **Custom Kratos UI** for user interface (sign-up, login, logout)
-   **MailSlurper** for email delivery during verification and recovery
-   **Kratos Migration** for database migrations

Important Environment Variables:

-   **DSN**: The connection string for PostgreSQL (`postgres://admin:admin@11.22.33.55:1234/kratos`)
-   **PORTS**: Ensure the necessary ports are open for Kratos, MailSlurper, and the UI.

### docker-compose-hydra.yml Configuration

**hydra service**: Runs the Ory Hydra service on ports 4444 (public) and 4445 (admin).
**hydra-migrate service**: Handles database migrations using SQLite.
**Volumes and Networks**: The hydra-sqlite volume stores SQLite database data, while the intranet network allows communication between the services.

### Kratos Configuration (`kratos.yml`)

-   **Self-Service Flows**: Configures flows like login, registration, password recovery, and verification.
-   **OAuth2**: Integrate with Google OAuth using the `oidc` provider. Replace the `client_id` and `client_secret` with your Google credentials.
-   **SMTP Configuration**: Ensure the SMTP connection is correct for MailSlurper or your chosen email provider.

### Hydra Configuration (`hydra.yml`)

The hydra.yml file configures Ory Hydra's services:

-   **CORS settings**: Enables CORS for both public and admin endpoints, allowing local requests from localhost and 127.0.0.1.
-   **OAuth URLs**: Defines the URLs for login, logout, and consent, connected with Ory Kratos.
-   **OIDC settings**: Sets up OIDC (OpenID Connect) with support for pairwise and public subject identifiers.
-   **Secrets**: Defines the system secret and pairwise salt (ensure you replace the default secret with a strong, unique value)

Important Configuration Changes

-   Change the system secret in the hydra.yml file (CHANGE_ME_TO_REAL_SECRET) to a strong, unique secret for production use.
-   Customize the urls section to match your application's endpoints.

## 4. Installation

### Step 1: Clone the Repository

```bash
git clone <repository-url>
cd <repository-directory>
```

### Step 2: Configure the Project

Update the following in the `kratos.yml` file:

-   Replace `client_id` and `client_secret` in the `oidc` section with your Google OAuth credentials.
-   Update the `DSN` environment variable in `docker-compose-kratos.yml` to match your PostgreSQL configuration.
-   Ensure the smtp.connection_uri is correctly configured in kratos.yml for MailSlurper or your SMTP provider.

### Step 3: Build and Run the Services

Run the following command to start the kratos:

```bash
docker-compose -f docker-compose-kratos.yml up -d
```

This will:

-   Set up the database migrations.
-   Launch Ory Kratos for identity management.
-   Start the custom Kratos UI.
-   Start MailSlurper for email handling.

Run the following command to start the hydra:

```bash
docker-compose -f docker-compose-hydra.yml up -d
```

This command will:

-   Launch the Hydra public and admin services.
-   Perform the necessary database migrations.

## 5. Usage

### Accessing the UI

After the services start, you can access the Kratos UI at:

```
http://127.0.0.1:4455
```

### Mail Server

Receive an email via MailSlurper at:

```
http://127.0.0.1:4436
```

## Ports and Their Usage

| Service                     | Port | Usage                                                                  |
| --------------------------- | ---- | ---------------------------------------------------------------------- |
| **Ory Kratos (Public API)** | 4433 | Public API for identity management (registration, login, etc.)         |
| **Ory Kratos (Admin API)**  | 4434 | Admin API for administrative tasks (manage identities, sessions, etc.) |
| **Custom Kratos UI**        | 4455 | Frontend UI for self-service flows like login, registration, etc.      |
| **MailSlurper (Web UI)**    | 4436 | Web interface to view emails sent during verification/recovery flows   |
| **MailSlurper (SMTP)**      | 4437 | SMTP server to simulate sending emails                                 |
| **Hydra Public API**        | 4444 | Public endpoint for OAuth 2.0 authorization requests.                  |
| **Hydra Admin API**         | 4445 | Admin endpoint for managing clients and configurations.                |
