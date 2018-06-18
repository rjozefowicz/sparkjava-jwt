package com.r6lab.sparkjava.jwt;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.r6lab.sparkjava.jwt.user.Role;
import com.r6lab.sparkjava.jwt.user.User;
import com.r6lab.sparkjava.jwt.user.UserPrincipal;
import com.r6lab.sparkjava.jwt.user.UserService;
import org.mindrot.jbcrypt.BCrypt;
import spark.Request;
import spark.Spark;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static spark.Spark.halt;

public final class SparkJwtExample {

    private static final String SECRET_JWT = "secret_jwt";
    private static final String BCRYPT_SALT = BCrypt.gensalt();
    private static final String TOKEN_PREFIX = "Bearer";

    private static final ScheduledExecutorService EXECUTOR_SERVICE = Executors.newSingleThreadScheduledExecutor();

    private final Gson gson = new GsonBuilder().create();
    private final UserService userService = new UserService();
    private final TokenService tokenService = new TokenService(SECRET_JWT);

    public void init() {
        createAdminUser();

        // PERIODIC TOKEN CLEAN UP
        EXECUTOR_SERVICE.scheduleAtFixedRate(() -> {
            System.out.println("Removing expired tokens");
            tokenService.removeExpired();
        }, 60, 60, TimeUnit.SECONDS); // every minute

        // AUTH FILTER
        Spark.before(new AuthFilter("/auth", tokenService));

        // REGISTRATION ENDPOINT
        Spark.post("/auth/registration", (request, response) -> {
            String json = request.raw().getReader().lines().collect(Collectors.joining());
            JsonObject jsonRequest = gson.fromJson(json, JsonObject.class);
            try {
                if (validatePost(jsonRequest)) {
                    userService.register(jsonRequest.get("userName").getAsString(),
                            BCrypt.hashpw(jsonRequest.get("password").getAsString(), BCRYPT_SALT),
                            jsonRequest.get("firstName").getAsString(),
                            jsonRequest.get("lastName").getAsString());
                    return "";
                } else {
                    response.status(400);
                }
            } catch (IllegalArgumentException e) {
                response.status(400);
            }
            return "";
        });

        // LOGIN ENDPOINT
        Spark.post("/auth/login", (request, response) -> {
            String json = request.raw().getReader().lines().collect(Collectors.joining());
            JsonObject jsonRequest = gson.fromJson(json, JsonObject.class);
            if (validatePost(jsonRequest)) {
                try {
                    String encryptedPassword = BCrypt.hashpw(jsonRequest.get("password").getAsString(), BCRYPT_SALT);
                    User user = userService.get(jsonRequest.get("userName").getAsString());
                    if (user.getPassword().equals(encryptedPassword)) {
                        response.header("Authorization", TOKEN_PREFIX + " " + tokenService.newToken(user));
                    }
                } catch (Exception e) {
                    response.status(401);
                }
            }
            return "";
        });

        // LOGOUT ENDPOINT
        Spark.post("/auth/logout", (request, response) -> {
            String authorizationHeader = request.headers("Authorization");
            tokenService.revokeToken(authorizationHeader.replace(TOKEN_PREFIX, ""));
            return "";
        });

        // REFRESH ENDPOINT
        Spark.post("/auth/token", (request, response) -> {
            String authorizationHeader = request.headers("Authorization");
            String token = authorizationHeader.replace(TOKEN_PREFIX, "");
            String userName = getUserNameFromToken(request);
            tokenService.revokeToken(token);
            String refreshedToken = tokenService.newToken(userService.get(userName));
            response.header("Authorization", TOKEN_PREFIX + " " + refreshedToken);
            return "";
        });

        // ME ENDPOINT
        Spark.get("/me", (request, response) -> {
            response.type("application/json");
            String userName = getUserNameFromToken(request);
            User user = userService.get(userName);
            JsonObject userJson = new JsonObject();
            userJson.addProperty("userName", user.getUsername());
            userJson.addProperty("firstName", user.getFirstName());
            userJson.addProperty("lastName", user.getLastName());
            return userJson.toString();
        });

        // ASSIGN ROLE
        Spark.post("/auth/role", (request, response) -> {
            if (hasRole(request, new Role[]{Role.ADMIN})) {
                String json = request.raw().getReader().lines().collect(Collectors.joining());
                JsonObject jsonRequest = gson.fromJson(json, JsonObject.class);
                if (jsonRequest.has("userName") && jsonRequest.has("role")) {
                    Role role = Role.valueOf(jsonRequest.get("role").getAsString());
                    if (role != null) {
                        User user = userService.get(jsonRequest.get("userName").getAsString());
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
        });

        // REVOKE ROLE
        Spark.delete("/auth/role", (request, response) -> {
            if (hasRole(request, new Role[]{Role.ADMIN})) {
                String json = request.raw().getReader().lines().collect(Collectors.joining());
                JsonObject jsonRequest = this.gson.fromJson(json, JsonObject.class);
                if (jsonRequest.has("userName") && jsonRequest.has("role")) {
                    Role role = Role.valueOf(jsonRequest.get("role").getAsString());
                    if (role != null) {
                        User user = this.userService.get(jsonRequest.get("userName").getAsString());
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
        });

        // PROTECTED ENDPOINT FOR DEVELOPER ROLE
        Spark.get("/protected/developer", (request, response) -> {
            if (hasRole(request, new Role[]{Role.DEVELOPER, Role.ADMIN})) {
                return "PROTECTED RESOURCE FOR DEVELOPER";
            } else {
                halt(401);
                return "";
            }
        });

        // PROTECTED ENDPOINT FOR DEVELOPER ROLE
        Spark.get("/protected/manager", (request, response) -> {
            if (hasRole(request, new Role[]{Role.MANAGER, Role.ADMIN})) {
                return "PROTECTED RESOURCE FOR MANAGER";
            } else {
                halt(401);
                return "";
            }
        });

        Spark.exception(Exception.class, (e, request, response) -> {
            System.err.println("Exception while processing request");
            e.printStackTrace();
        });

    }

    private void createAdminUser() {
        userService.register("admin", BCrypt.hashpw("admin", BCRYPT_SALT), null, null); //ADMIN USER
        User admin = userService.get("admin");
        admin.assignRole(Role.ADMIN);
        userService.update(admin);
    }

    private UserPrincipal getUserPrincipal(Request request) {
        String authorizationHeader = request.headers("Authorization");
        String token = authorizationHeader.replace(TOKEN_PREFIX, "");
        return tokenService.getUserPrincipal(token);
    }

    private String getUserNameFromToken(Request request) {
        String authorizationHeader = request.headers("Authorization");
        String token = authorizationHeader.replace(TOKEN_PREFIX, "");
        return tokenService.getUserPrincipal(token).getUserName();
    }

    private boolean validatePost(JsonObject jsonRequest) {
        return jsonRequest != null && jsonRequest.has("userName") && jsonRequest.has("password");
    }

    private boolean hasRole(Request request, Role[] roles) {
        List<Role> userRoles = getUserPrincipal(request).getRoles();
        return userRoles.stream().filter(Arrays.asList(roles)::contains).findAny().isPresent();
    }


    // BOOTSTRAP
    public static void main(String[] args) {
        SparkJwtExample sparkJwtExample = new SparkJwtExample();
        sparkJwtExample.init();
    }

}
