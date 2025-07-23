package ru.romanov.auth.model;

import lombok.Getter;

@Getter
public enum Role {
    ADMIN("admin"),
    PREMIUM_USER("premium_user"),
    GUEST("guest");

    private final String value;

    Role(String value) {
        this.value = value;
    }
}
