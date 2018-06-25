# sparkjava-jwt
Example SparkJava - JWT integration

# tech
![](https://img.shields.io/badge/java%208-%E2%9C%93-blue.svg)
![](https://img.shields.io/badge/sparkjava-✓-blue.svg)
![](https://img.shields.io/badge/jwt-✓-blue.svg)

## Public available endpoints

| ENDPOINT | HTTP METHOD | PARAMS | DESCRIPTION |
| ------ | ------ | ------ | ------ |
| /auth/register | POST | JSON body mandatory fields: userName, password. Additional fields firstName, secondName | New user registration |
| /auth/login | POST | JSON body mandatory fields: userName, password | User login |

## Additional JWT endpoints

**HTTP Header:** *Authorization: Bearer JWTToken*

| ENDPOINT | HTTP METHOD | PARAMS | DESCRIPTION |
| ------ | ------ | ------ | ------ |
| /auth/token | POST |  | JWT token refresh |
| /auth/logout | POST |  | JWT token revocation |
| /auth/me | GET |  | User details |

## Roles

#### Predefined user roles:
* ADMIN
* MANAGER
* DEVELOPER

#### Endpoints for Role management:

ENDPOINT | HTTP METHOD | PARAMS | DESCRIPTION |
| ------ | ------ | ------ | ------ |
| /auth/roles | POST | JSON body mandatory fields: userName, role | Add new Role to user |
| /auth/roles | DELETE | JSON body mandatory fields: userName, role | Revoke Role from User |

## Admin user

Predefined Admin user (admin/admin)

## Additional 

Cron job (every minute) to clean up revoked JWT Tokens
