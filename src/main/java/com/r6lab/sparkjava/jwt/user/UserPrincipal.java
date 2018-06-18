package com.r6lab.sparkjava.jwt.user;

import java.util.List;

public final class UserPrincipal {
    private final String userName;
    private final List<Role> roles;

    private UserPrincipal(String userName, List<Role> roles) {
        this.userName = userName;
        this.roles = roles;
    }

    public String getUserName() {
        return userName;
    }

    public List<Role> getRoles() {
        return roles;
    }

    public static UserPrincipal of(String userName, List<Role> roles) {
        return new UserPrincipal(userName, roles);
    }
}
