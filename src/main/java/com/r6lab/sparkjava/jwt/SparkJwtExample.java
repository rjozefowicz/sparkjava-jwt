package com.r6lab.sparkjava.jwt;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.r6lab.sparkjava.jwt.user.User;
import com.r6lab.sparkjava.jwt.user.UserService;
import org.mindrot.jbcrypt.BCrypt;
import spark.Route;
import spark.Spark;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

public final class SparkJwtExample {

    private static final ScheduledExecutorService EXECUTOR_SERVICE = Executors.newSingleThreadScheduledExecutor();

    private static final String SECRET_JWT = "secret_jwt";
    private static final String BCRYPT_SALT = BCrypt.gensalt();

    private static final String TOKEN_PREFIX = "Bearer";

    public static void main(String[] args) {

        Gson gson = new GsonBuilder().create();
        UserService userService = new UserService();
        TokenService tokenService = new TokenService(SECRET_JWT);

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
                    if (userService.get(jsonRequest.get("userName").getAsString()).getPassword().equals(encryptedPassword)) {
                        response.header("Authorization", TOKEN_PREFIX + " " + tokenService.newToken(jsonRequest.get("userName").getAsString()));
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
            String userName = tokenService.getUserName(token);
            tokenService.revokeToken(token);
            String refreshedToken = tokenService.newToken(userName);
            response.header("Authorization", TOKEN_PREFIX + " " + refreshedToken);
            return "";
        });

        // ME ENDPOINT
        Spark.get("/me", (request, response) -> {
            response.type("application/json");
            String authorizationHeader = request.headers("Authorization");
            String token = authorizationHeader.replace(TOKEN_PREFIX, "");
            String userName = tokenService.getUserName(token);
            User user = userService.get(userName);
            JsonObject userJson = new JsonObject();
            userJson.addProperty("userName", user.getUsername());
            userJson.addProperty("firstName", user.getFirstName());
            userJson.addProperty("lastName", user.getLastName());
            return userJson.toString();
        });

        // PROTECTED ENDPOINT
        Spark.get("/protected", (request, response) -> "PROTECTED RESOURCE");

        Spark.exception(Exception.class, (e, request, response) -> {
            System.err.println("Exception while processing request");
            e.printStackTrace();
        });

    }

    private static boolean validatePost(JsonObject jsonRequest) {
        return jsonRequest != null && jsonRequest.has("userName") && jsonRequest.has("password");
    }

}
