package com.r6lab.sparkjava.jwt.user;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public final class UserService {

    private final List<User> users = new CopyOnWriteArrayList<>();

    public final void register(String userName, String password, String firstName, String lastName) {
        if (users.stream().filter(user -> user.getUsername().equals(userName)).findAny().isPresent()) {
            throw new IllegalArgumentException("User already exists");
        }
        users.add(User.of(userName, password, firstName, lastName, new ArrayList<>()));
    }

    public final User get(String userName) {
        return users
                .stream()
                .filter(user -> user.getUsername().equals(userName))
                .findAny()
                .orElseThrow(() -> new IllegalStateException("User does not exist"));
    }

    public final void update(User user) {
        users.add(user);
    }

}
