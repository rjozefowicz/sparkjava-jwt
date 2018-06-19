package com.r6lab.sparkjava.jwt.controller;

import com.r6lab.sparkjava.jwt.TokenService;
import com.r6lab.sparkjava.jwt.user.Role;
import com.r6lab.sparkjava.jwt.user.UserPrincipal;
import spark.Request;

import java.util.Arrays;
import java.util.List;

public abstract class AbstractTokenController {

    private static final String TOKEN_PREFIX = "Bearer";

    private final TokenService tokenService;

    public AbstractTokenController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    protected UserPrincipal getUserPrincipal(Request request) {
        String authorizationHeader = request.headers("Authorization");
        String token = authorizationHeader.replace(TOKEN_PREFIX, "");
        return tokenService.getUserPrincipal(token);
    }

    protected boolean hasRole(Request request, Role[] roles) {
        if (roles.length == 0) {
            return true;
        }
        List<Role> userRoles = getUserPrincipal(request).getRoles();
        return userRoles.stream().filter(Arrays.asList(roles)::contains).findAny().isPresent();
    }

    protected String getUserNameFromToken(Request request) {
        String authorizationHeader = request.headers("Authorization");
        String token = authorizationHeader.replace(TOKEN_PREFIX, "");
        return tokenService.getUserPrincipal(token).getUserName();
    }

}
