package com.r6lab.sparkjava.jwt.controller;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.r6lab.sparkjava.jwt.AuthFilter;
import com.r6lab.sparkjava.jwt.TokenService;
import com.r6lab.sparkjava.jwt.user.Role;
import com.r6lab.sparkjava.jwt.user.User;
import com.r6lab.sparkjava.jwt.user.UserService;
import org.mindrot.jbcrypt.BCrypt;
import spark.Request;
import spark.Response;
import spark.Spark;

import java.io.IOException;
import java.util.stream.Collectors;

import static spark.Spark.before;
import static spark.Spark.get;
import static spark.Spark.halt;
import static spark.Spark.post;

public class AuthController extends AbstractTokenController {

    private static final String ROLE_PROPERTY = "role";
    private static final String TOKEN_PREFIX = "Bearer";
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String USER_NAME_PROPERTY = "userName";
    private static final String FIRST_NAME_PROPERTY = "firstName";
    private static final String LAST_NAME_PROPERTY = "lastName";
    private static final String PASSWORD_PROPERTY = "password";
    private static final String AUTH_ENDPOINT_PREFIX = "/auth";

    private static final String BCRYPT_SALT = BCrypt.gensalt();

    private final Gson gson;
    private final UserService userService;
    private final TokenService tokenService;

    public AuthController(Gson gson, UserService userService, TokenService tokenService) {
        super(tokenService);
        this.gson = gson;
        this.userService = userService;
        this.tokenService = tokenService;
    }

    public void init() {
        createAdminUser();

        // AUTH FILTER
        before(new AuthFilter(AUTH_ENDPOINT_PREFIX, tokenService));

        // REGISTRATION ENDPOINT
        post(AUTH_ENDPOINT_PREFIX + "/registration", (request, response) -> register(request, response));

        // LOGIN ENDPOINT
        post(AUTH_ENDPOINT_PREFIX + "/login", (request, response) -> login(request, response));

        // LOGOUT ENDPOINT
        post(AUTH_ENDPOINT_PREFIX + "/logout", (request, response) -> logout(request));

        // REFRESH ENDPOINT
        post(AUTH_ENDPOINT_PREFIX + "/token", (request, response) -> refresh(request, response));

        // ME ENDPOINT
        get(AUTH_ENDPOINT_PREFIX + "/me", (request, response) -> me(request, response));

        // ASSIGN ROLE_PROPERTY
        post(AUTH_ENDPOINT_PREFIX + "/roles", (request, response) -> assignRole(request));

        // REVOKE ROLE_PROPERTY
        Spark.delete(AUTH_ENDPOINT_PREFIX + "/roles", (request, response) -> revokeRole(request));

    }

    private String revokeRole(Request request) throws IOException {
        if (hasRole(request, new Role[]{Role.ADMIN})) {
            String json = request.raw().getReader().lines().collect(Collectors.joining());
            JsonObject jsonRequest = this.gson.fromJson(json, JsonObject.class);
            if (jsonRequest.has(USER_NAME_PROPERTY) && jsonRequest.has(ROLE_PROPERTY)) {
                Role role = Role.valueOf(jsonRequest.get(ROLE_PROPERTY).getAsString());
                if (role != null) {
                    User user = this.userService.get(jsonRequest.get(USER_NAME_PROPERTY).getAsString());
                    if (user != null) {
                        user.revokeRole(role);
                        this.userService.update(user);
                    }
                }
            }
        } else {
            halt(401);
        }

        return "";
    }

    private String assignRole(Request request) throws IOException {
        if (hasRole(request, new Role[]{Role.ADMIN})) {
            String json = request.raw().getReader().lines().collect(Collectors.joining());
            JsonObject jsonRequest = gson.fromJson(json, JsonObject.class);
            if (jsonRequest.has(USER_NAME_PROPERTY) && jsonRequest.has(ROLE_PROPERTY)) {
                Role role = Role.valueOf(jsonRequest.get(ROLE_PROPERTY).getAsString());
                if (role != null) {
                    User user = userService.get(jsonRequest.get(USER_NAME_PROPERTY).getAsString());
                    if (user != null) {
                        user.assignRole(role);
                        userService.update(user);
                    }
                }
            }
        } else {
            halt(401);
        }

        return "";
    }

    private String me(Request request, Response response) {
        response.type("application/json");
        String userName = getUserNameFromToken(request);
        User user = userService.get(userName);
        JsonObject userJson = new JsonObject();
        userJson.addProperty(USER_NAME_PROPERTY, user.getUsername());
        userJson.addProperty(FIRST_NAME_PROPERTY, user.getFirstName());
        userJson.addProperty(LAST_NAME_PROPERTY, user.getLastName());
        return userJson.toString();
    }

    private String refresh(Request request, Response response) {
        String authorizationHeader = request.headers(AUTHORIZATION_HEADER);
        String token = authorizationHeader.replace(TOKEN_PREFIX, "");
        String userName = getUserNameFromToken(request);
        tokenService.revokeToken(token);
        String refreshedToken = tokenService.newToken(userService.get(userName));
        response.header(AUTHORIZATION_HEADER, TOKEN_PREFIX + " " + refreshedToken);
        return "";
    }

    private String logout(Request request) {
        String authorizationHeader = request.headers(AUTHORIZATION_HEADER);
        tokenService.revokeToken(authorizationHeader.replace(TOKEN_PREFIX, ""));
        return "";
    }

    private String login(Request request, Response response) throws IOException {
        String json = request.raw().getReader().lines().collect(Collectors.joining());
        JsonObject jsonRequest = gson.fromJson(json, JsonObject.class);
        if (validatePost(jsonRequest)) {
            try {
                String encryptedPassword = BCrypt.hashpw(jsonRequest.get(PASSWORD_PROPERTY).getAsString(), BCRYPT_SALT);
                User user = userService.get(jsonRequest.get(USER_NAME_PROPERTY).getAsString());
                if (user.getPassword().equals(encryptedPassword)) {
                    response.header(AUTHORIZATION_HEADER, TOKEN_PREFIX + " " + tokenService.newToken(user));
                }
            } catch (Exception e) {
                response.status(401);
            }
        }
        return "";
    }

    private String register(Request request, Response response) throws IOException {
        String json = request.raw().getReader().lines().collect(Collectors.joining());
        JsonObject jsonRequest = gson.fromJson(json, JsonObject.class);
        try {
            if (validatePost(jsonRequest)) {
                userService.register(jsonRequest.get(USER_NAME_PROPERTY).getAsString(),
                        BCrypt.hashpw(jsonRequest.get(PASSWORD_PROPERTY).getAsString(), BCRYPT_SALT),
                        jsonRequest.has(FIRST_NAME_PROPERTY) ? jsonRequest.get(FIRST_NAME_PROPERTY).getAsString() : null,
                        jsonRequest.has(LAST_NAME_PROPERTY) ? jsonRequest.get(LAST_NAME_PROPERTY).getAsString() : null);
                return "";
            } else {
                response.status(400);
            }
        } catch (IllegalArgumentException e) {
            response.status(400);
        }
        return "";
    }

    private void createAdminUser() {
        userService.register("admin", BCrypt.hashpw("admin", BCRYPT_SALT), null, null); //ADMIN USER
        User admin = userService.get("admin");
        admin.assignRole(Role.ADMIN);
        userService.update(admin);
    }

    private boolean validatePost(JsonObject jsonRequest) {
        return jsonRequest != null && jsonRequest.has(USER_NAME_PROPERTY) && jsonRequest.has(PASSWORD_PROPERTY);
    }

}
