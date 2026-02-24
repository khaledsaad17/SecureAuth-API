# 🔐 Secure Auth API

A robust, production-ready authentication and authorization microservice built with NestJS. This API provides a comprehensive set of security features including JWT tokens, 2FA, OAuth2 (Google), rate limiting, audit logging, and multi-project support. It is designed to be a reusable auth server for multiple client applications.

## ✨ Features

- **Complete Authentication Flow**
  - User Registration with Email Verification
  - Login with Password
  - JWT Access & Refresh Tokens
  - Forgot Password / Reset Password
  - Logout

- **Advanced Security**
  - Two-Factor Authentication (2FA) via Google Authenticator (TOTP)
  - OAuth2 Google Login (with temporary token storage)
  - Rate Limiting (Throttling) on all endpoints
  - Helmet.js for secure headers
  - Input validation and sanitization (DTOs with whitelist)

- **Multi-Tenancy / Multi-Project Support**
  - Isolate users by `project_identify` - allows one auth server to serve multiple frontend apps.
  - Users can belong to multiple projects but maintain a single account (email/password).

- **Audit Trail**
  - Automatic logging of critical actions (Login, Logout, 2FA verification, Password reset).
  - Dedicated endpoints for users and admins to view logs.

- **Developer Experience**
  - Full Swagger/OpenAPI documentation at `/docs`.
  - Environment-based configuration.
  - Ready for Docker deployment.

## 🛠️ Tech Stack

- **Framework:** [NestJS](https://nestjs.com/) (Node.js)
- **Database:** MongoDB with Mongoose ODM
- **Cache & Temp Storage:** Redis (for OAuth tokens and rate limiting)
- **Security:** JWT, bcrypt, Speakeasy (2FA), Helmet, express-rate-limit (via Throttler)
- **Documentation:** Swagger UI
- **Language:** TypeScript

## 📚 API Documentation

Interactive Swagger documentation is available at:
url: http://localhost:3001/docs

- **Test all endpoints directly from your browser
- **JWT authentication supported via "Authorize" button
- **Complete request/response schemas for all DTOs

## 🚀 Getting Started

### Prerequisites

- Node.js (v18 or later)
- npm or yarn
- MongoDB instance (local or Atlas)
- Redis server (local or cloud)
- A Google Cloud Project (for OAuth, optional)

### Installation

1.  **Clone the repository**
    ```bash
    git clone https://github.com/khaledsaad17/SecureAuth-API
    cd secure-auth-api
    ```

2.  **Install dependencies**
    ```bash
    npm install
    ```

3.  **Set up environment variables**
    Create a `.env` file in the root directory. Use the following template:

    ```env
    # Server
    PORT=3001

    # Database (MongoDB)
    DATABASE_URL=mongodb://localhost:27017/secure-auth
    DATABASE_NAME=secure-auth

    # Redis
    REDIS_HOST=localhost
    REDIS_PORT=6379

    # JWT Secrets (Use strong, random strings in production)
    JWT_ACCESS_TOKEN_SECRET=your_super_secret_access_key_change_me
    JWT_REFRESH_TOKEN_SECRET=your_super_secret_refresh_key_change_me

    # Email (for verification & password reset)
    EMAIL_HOST=smtp.gmail.com
    EMAIL_PORT=587
    EMAIL_USER=your-email@gmail.com
    EMAIL_PASSWORD=your-app-password

    # Frontend URL (for redirects after OAuth)
    FRONTEND_URL=http://localhost:3000

    # Google OAuth
    GOOGLE_CLIENT_ID=your_google_client_id.apps.googleusercontent.com
    GOOGLE_CLIENT_SECRET=your_google_client_secret
    ```

4.  **Run with Docker (Recommended)**

    Make sure Docker and Docker Compose are installed. The project includes a `docker-compose.yml` file (you may need to create one if not present) that sets up Node, MongoDB, and Redis.

    ```bash
    # Build and start all services
    docker-compose up --build
    ```

5.  **Run locally (without Docker)**
    - Ensure MongoDB and Redis are running on your machine.
    - Start the development server:
    ```bash
    npm run start:dev
    ```

6.  **Access the API**
    - API Base: `http://localhost:3001/api`
    - Swagger Documentation: `http://localhost:3001/docs`

## 📚 API Documentation

Once the server is running, visit `/docs` for an interactive Swagger UI where you can test all endpoints.

**Key Endpoint Categories:**
- `POST /auth/register` - Create a new user.
- `POST /auth/login` - Authenticate and get tokens.
- `GET /auth/refresh` - Get a new access token using a refresh token.
- `GET /auth/enable-2fa` - Enable 2FA and get a QR code.
- `GET /auth/google` - Initiate Google OAuth login.
- `GET /audit/logs` - Get audit logs for the current user.
- `GET /audit/admin/logs/:userId` - (Admin) Get logs for any user.

## 🗂️ Project Structure
```
src/
├── auth/ # Core authentication module
│ ├── DTO/ # Data Transfer Objects (validation)
│ ├── Decorator/ # Custom decorators (@GetUser, @SkipAuth)
│ ├── guards/ # JWT, RefreshToken, GoogleAuth, Role guards
│ ├── strategies/ # JWT and Google OAuth strategies
│ └── auth.service.ts # Main business logic
├── users/ # User management
│ ├── DTO/ # User creation, login, password reset
│ ├── user.schema.ts # Mongoose schema for User
│ └── users.service.ts
├── usersprojects/ # usersprojects management
│ ├── usersprojects.schema.ts # Mongoose schema for usersprojects
│ └── usersprojects.service.ts
├── audit/ # Audit logging
│ ├── audit.schema.ts
│ ├── audit.service.ts
│ └── audit.controller.ts
├── conf-module/ # Configuration modules (environment)
└── main.ts # Application entry point

```
## 🔒 Security Considerations

- **Passwords** are hashed using bcrypt.
- **JWT tokens** are signed with separate secrets for access and refresh tokens.
- **Refresh tokens** are stored securely and can be revoked (session management is implied).
- **2FA secrets** are encrypted/hashed before storage.
- **Rate limiting** is applied globally to prevent brute-force attacks.
- **Input validation** is strict; extra fields are stripped automatically.

## 📦 Deployment

This API is containerized and can be deployed to any cloud provider (AWS, GCP, DigitalOcean) or orchestration platform (Kubernetes, Docker Swarm).

### Using Docker Compose (Production-like)

1.  Set up your production environment variables (use a secrets manager or `.env` file on the server).
2.  Run:
    ```bash
    docker-compose -f docker-compose.prod.yml up -d
    ```
    *(Note: You may need to create a production-specific compose file with different build commands and restart policies.)*

### Environment Variables for Production

Ensure the following variables are strong and secure:
- `JWT_ACCESS_TOKEN_SECRET`
- `JWT_REFRESH_TOKEN_SECRET`
- `DATABASE_URL` (should point to your production DB)
- `REDIS_HOST` / `REDIS_PORT`

## 👥 Contributing / Customization

This API is designed to be a standalone microservice. To integrate it with your own projects:

1.  Set the `project_identify` field during registration/login to separate user bases.
2.  Configure CORS to accept requests from your frontend domains.
3.  Use the provided JWT tokens to authenticate requests to your other backend services (by validating the token against this auth service or using a shared secret).

## 📄 License

This project is licensed under the MIT License.

## 📧 Contact

Your Name - [khaledsaad_17@outlook.com](mailto:khaledsaad_17@outlook.com)

Project Link: [https://github.com/yourusername/secure-auth-api](https://github.com/khaledsaad17/SecureAuth-API)


