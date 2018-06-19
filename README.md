# sparkjava-jwt
Example SparkJava - JWT integration

## Public available endpoints

* /registration - HTTP POST - new user registration (JSON body mandatory fields: userName, password. Additional fields firstName, secondName)
* /login - HTTP POST - user login (JSON body mandatory fields: userName, password)

## Additional JWT endpoints

HTTP Header: Authorization: Bearer JWTToken

* /token - HTTP POST - JWT Token refresh
* /logout - HTTP POST - JWT Token revocation
* /me - HTTP GET - User details

## Roles

Defined user roles: ADMIN, MANAGER, DEVELOPER

Endpoints for Role management:

* /auth/role - HTTP POST - add new ROLE to user (JSON body mandatory fields: userName, role)
* /auth/role - HTTP DELETE - revoke ROLE from user (JSON body mandatory fields: userName, role)

## Admin user

Predefined Admin user (admin/admin)

## Additional 

Cron job (every minute) to clean up revoked JWT Tokens
