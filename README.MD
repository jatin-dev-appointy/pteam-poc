# Ory Kratos Authentication and Authorization

## Introduction

This project is a containerized setup for running ORY Kratos and ORY Hydra locally for development and testing purposes.

## Prerequisites

Ensure you have the following tools installed before proceeding:

- **Docker**: To run the services in containers.
- **Docker Compose**: To manage multi-container Docker applications.
- **PostgreSQL**: A Cloud/Local PostgreSQL Instance Contains two seperate databases for Hydra/Kratos.

```text
Note: You also need to configure an OAuth2 provider, like Google, if you wish to use OAuth login.
```

## Project Setup

### Step 1 - Clone this repository to your local machine

```bash
git clone https://github.com/jatin-dev-appointy/pteam-poc.git

cd pteam-poc
```

### Step 2 - Configure Kratos/Hydra

```text
Config Steps ...
```

### Step 3 - Generate Custom Docker Images

`Note: Navigate to the Root Directory`

- Custom Auth Project - A Custom Backend Server which communicates to ORY Hydra/Kratos

```bash
docker build custom-auth-interface -t custom-auth-interface:1.0
```

- Custom Kratos UI - A Custom user interface for Kratos, handling registration, login, and logout screens.

```bash
docker build custom-kratos-ui -t custom-kratos-ui:1.0
```

### Step 4 - Run All the Docker Images via Docker Compose

```bash
docker-compose -f docker-compose up -d
```

This will

- Set up the database migrations of Hydra/Kratos Schema and Tables
- Launch Ory Kratos/Hydra Admin/Public Services for Authentication.
- Start MailSlurper Test Service for Email Handling. (View Sent Emails on <http://127.0.0.1:4436>)
- Start the Custom Kratos UI.
- Start the Cuustom Auth Project i.e Custom Backend Server which communicates to ORY Hydra/Kratos

#### Step 5 - Access the Service

```bash
EntryPoint - http://127.0.0.1:8080
```

##### Ports and Their Usage

| Service                     | Port | Usage                                                                  |
| --------------------------- | ---- | ---------------------------------------------------------------------- |
| **Ory Kratos (Public API)** | 4433 | Public API for identity management (registration, login, etc.)         |
| **Ory Kratos (Admin API)**  | 4434 | Admin API for administrative tasks (manage identities, sessions, etc.) |
| **Custom Kratos UI**        | 4455 | Frontend UI for self-service flows like login, registration, etc.      |
| **MailSlurper (Web UI)**    | 4436 | Web interface to view emails sent during verification/recovery flows   |
| **MailSlurper (SMTP)**      | 4437 | SMTP server to simulate sending emails                                 |
| **Hydra Public API**        | 4444 | Public endpoint for OAuth 2.0 authorization requests.                  |
| **Hydra Admin API**         | 4445 | Admin endpoint for managing clients and configurations.                |

## Getting Started

### Step 1 - Create Hydra Client

```text
NOTE: This steps will fetch CLIENT_ID, CLIENT_SECRET that will used in Custom-Auth-PRoject Configurations 
```

```bash
curl --location 'http://127.0.0.1:4445/admin/clients' \
--header 'Content-Type: application/json' \
--header 'Accept: application/json' \
--data '{
  "client_name": "p-team",
  "redirect_uris": [
    "http://127.0.0.1:8080/callback",
    "http://127.0.0.1:8080/logout-callback",
    "http://127.0.0.1:8080/logout-middleware"
  ],
  "grant_types": [
    "authorization_code",
    "refresh_token"
  ],
  "response_types": [
    "code",
    "id_token"
  ],
  "scope": "openid offline profile",
  "post_logout_redirect_uris": [
    "http://127.0.0.1:8080/logout-callback"
  ]
}'
```

## References

- <https://www.ory.sh/docs/kratos/install>
- <https://www.ory.sh/docs/hydra/self-hosted/install>
