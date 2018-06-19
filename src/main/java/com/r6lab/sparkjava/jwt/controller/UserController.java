package com.r6lab.sparkjava.jwt.controller;

import com.r6lab.sparkjava.jwt.TokenService;
import com.r6lab.sparkjava.jwt.user.Role;

import static spark.Spark.get;
import static spark.Spark.halt;

public class UserController extends AbstractTokenController {

    public UserController(TokenService tokenService) {
        super(tokenService);
    }

    public void init() {
        // PROTECTED ENDPOINT FOR DEVELOPER ROLE_PROPERTY
        get("/protected/developer", (request, response) -> {
            if (hasRole(request, new Role[]{Role.DEVELOPER, Role.ADMIN})) {
                return "PROTECTED RESOURCE FOR DEVELOPER";
            } else {
                halt(401);
                return "";
            }
        });

        // PROTECTED ENDPOINT FOR MANAGER ROLE_PROPERTY
        get("/protected/manager", (request, response) -> {
            if (hasRole(request, new Role[]{Role.MANAGER, Role.ADMIN})) {
                return "PROTECTED RESOURCE FOR MANAGER";
            } else {
                halt(401);
                return "";
            }
        });

        // PROTECTED ENDPOINT FOR ADMIN ROLE_PROPERTY
        get("/protected/admin", (request, response) -> {
            if (hasRole(request, new Role[]{Role.ADMIN})) {
                return "PROTECTED RESOURCE FOR ADMIN";
            } else {
                halt(401);
                return "";
            }
        });

        // PROTECTED ENDPOINT FOR ALL ROLES
        get("/protected/all", (request, response) -> {
            if (hasRole(request, new Role[]{})) {
                return "PROTECTED RESOURCE FOR ALL ROLES";
            } else {
                halt(401);
                return "";
            }
        });
    }
}
