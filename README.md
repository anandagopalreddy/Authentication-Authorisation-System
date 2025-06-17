# Authentication-Authorisation-System
This project implements a secure Authentication and Authorization system using PyJWT (HS256 algorithm) for token-based authentication and PyCryptodome for cryptographic password hashing. During registration, user passwords are securely hashed using algorithms like SHA-256 or PBKDF2 from PyCryptodome and then stored safely in the database.

Upon successful login, the system generates a JWT (JSON Web Token) signed with a symmetric secret key using the HS256 algorithm. This token includes claims such as the user's ID, username, and role, and is returned to the client. All protected routes require the JWT to be included in the Authorization header for access.

The system verifies the token’s signature and expiration on each request to ensure the user is authenticated. Role-based access control can be enforced using custom claims inside the token. This solution is ideal for APIs or microservices requiring lightweight, stateless, and secure user authentication without relying on sessions or server-side storage.

It follows security best practices, including:

Strong password hashing using PyCryptodome

Token signing and verification using HS256 (symmetric key)

Token expiration and validation

Clean separation of registration, login, and protected resources

Scalable and easy-to-extend structure for role-based permissions

