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

### Step 2 - Configurations for Kratos/Hydra

There are four main files to configure:

- **`docker-compose.yml`**: Defines the containers, including Ory hydra & Kratos, UI, Backend, MailSlurper and migrations.
- **`kratos.yml`**: The Kratos configuration file that defines the services, identity schemas, and email settings.
- **`hydra.yml`**: Thw Hydra configuration file to handle OAuth 2.0 and OpenID Connect server.
- **`identity-schema.json`**: This file defines the identity schema for users in Kratos, including traits like email and password.

#### 1. (Docker Compose Configurations) - `docker-compose.yml`

- **custom-auth-interface**: A custom backend server communicate with ory kratos and hydra.

  - Important Environment Variables:
    - `CLIENT_ID`, `CLIENT_SECRET`: Used to configure OAuth2 client credentials.
    - `HYDRA_PUBLIC_URL`, `HYDRA_ADMIN_URL`: URLs for connecting to Hydra's public and admin interfaces.
    - `KRATOS_PUBLIC_URL`: URL to Kratos' public interface.

- **hydra**:

  - **hydra service**: Runs the Ory Hydra service on ports 4444 (public) and 4445 (admin).
  - **hydra-migrate service**: Handles database migrations using SQLite.
  - **Volumes and Networks**: The hydra-sqlite volume stores SQLite database data, while the intranet network allows communication between the services.
  - Important Environment Variables:
    - **DSN**: The connection string for PostgreSQL (`postgres://admin:admin@11.22.33.55:1234/hydra`)

- **kratos**:

  - **Ory Kratos** to handle user identities and self-service flows like registration and login.
  - **Kratos Migration** for database migrations
  - Important Environment Variables:
    - **DSN**: The connection string for PostgreSQL (`postgres://admin:admin@11.22.33.55:1234/kratos`)

- **kratos-custom-ui**:

  - Custom user interface for Kratos, handling registration, login, and logout screens.
  - Important Environment Variables: - KRATOS_PUBLIC_URL, KRATOS_BROWSER_URL, HYDRA_ADMIN_URL

- **mailslurper**:
  - A mail server for testing, used by Kratos to send verification and recovery emails.

#### 2. (Kratos Configuration) - `kratos.yml`

- **Self-Service Flows**: Configures flows like login, registration, password recovery, and verification.
- **OAuth2**: Integrate with Google OAuth using the `oidc` provider. Replace the `client_id` and `client_secret` with your Google credentials.
- **SMTP Configuration**: Ensure the SMTP connection is correct for MailSlurper or your chosen email provider.

#### 3. (Hydra Configuration) - `hydra.yml`

##### The hydra.yml file configures Ory Hydra's services

- **CORS settings**: Enables CORS for both public and admin endpoints, allowing local requests from localhost and 127.0.0.1.
- **OAuth URLs**: Defines the URLs for login, logout, and consent, connected with Ory Kratos.
- **OIDC settings**: Sets up OIDC (OpenID Connect) with support for pairwise and public subject identifiers.
- **Secrets**: Defines the system secret and pairwise salt (ensure you replace the default secret with a strong, unique value)

##### Important Configuration Changes

- Change the system secret in the `hydra.yml` file (CHANGE_ME_TO_REAL_SECRET) to a strong, unique secret for production use.
- Customize the urls section to match your application's endpoints.

#### 4. (Identity Schema Configuration) - `identity.schema.json`

##### This file defines the identity schema for users in Kratos, including traits like email and password

- Defines required and optional user traits (email, first name, last name, etc.)
- Configure the primary identifier for password and code-based authentication
- Sets up verification and recovery flows

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

## Dynamic Login Flow Based on Query Parameters

To customize the login flow and conditionally skip specific identity providers, add a `skip_providers` query parameter to the login URL. The value of this parameter should be base64-encoded.

### How it Works

1. **Passing Query Parameter:**  
   When generating the login flow, the query parameter `skip_providers` (e.g., `skip_providers=U0tJUEdH`) is passed along with other standard parameters.

2. **Flow Generation:**  
   Ory Kratos generates the login flow and includes the `skip_providers` parameter in the flow `request_url` stored in the database.

3. **Checking Flow:**  
   During the rendering of the login page, the system checks if the flow associated with the `flow_id` contains the `skip_providers` parameter.

4. **Skipping Providers:**  
   If the parameter exists, the login page skips the specified identity providers based on a pre-defined mapping of provider names.

### Example

For instance, the following URL skips a google login during the login flow:

```bash
http://127.0.0.1:4455/login?skip_providers=U0tJUEdH
```

## CAPTCHA Implementation

In this proof of concept (POC), we utilize Google reCAPTCHA to enhance the security of our application. This implementation can also be adapted to use other CAPTCHA solutions, such as Cloudflare Turnstile, if desired.

### Steps for Implementation

1. **Obtain reCAPTCHA Credentials:**
   - Sign up for Google reCAPTCHA and obtain your **site key** and **secret key** from the [Google reCAPTCHA website](https://www.google.com/recaptcha).

2. **Implementation of Invisible reCAPTCHA:**
   - We have implemented **invisible reCAPTCHA**, which will only be displayed if necessary, based on user interactions.

3. **Flow of CAPTCHA Verification:**
   - When a user clicks the **Submit** button, the following steps are executed:
     - If CAPTCHA verification is deemed necessary, the reCAPTCHA will be triggered.
     - Upon successful completion of the CAPTCHA, a token will be generated by Google.
     - This token is then sent to our backend (BE) for verification to ensure the request is genuine.
     - The backend will make an API call to Google, providing the received token along with the **secret key**.
     - If the CAPTCHA response is successful, a login request will be sent to Ory Kratos with the form data.
     - If the CAPTCHA verification fails, an appropriate message indicating that the CAPTCHA has failed will be displayed to the user.

## API Specification

```bash
https://documenter.getpostman.com/view/20290085/2sAXqwYKVU#5a5cda9e-67ac-47af-8d03-4f55395c6e2f
```

API Postman Collection can be found at `./poc-pteam.postman_collection.json`

## References

- <https://www.ory.sh/docs/kratos/install>
- <https://www.ory.sh/docs/hydra/self-hosted/install>
