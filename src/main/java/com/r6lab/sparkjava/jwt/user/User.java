package com.r6lab.sparkjava.jwt.user;

public final class User {

    private final String username;
    private final String password;
    private final String firstName;
    private final String lastName;

    private User(String username, String password, String firstName, String lastName) {
        this.username = username;
        this.password = password;
        this.firstName = firstName;
        this.lastName = lastName;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getFirstName() {
        return firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public static final User of(String username, String password, String firstName, String lastName) {
        return new User(username, password, firstName, lastName);
    }
}
