package com.jwt.domin.member;

import java.util.Collection;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

@Getter
public class UserPrinciple extends User {

    private static final String PASSWORD_ERASED_VALUE = "[PASSWORD_ERASED]";
    private final String email;

    public UserPrinciple(String email, String username, Collection<? extends GrantedAuthority> authorities) {
        super(username, PASSWORD_ERASED_VALUE, authorities);
        this.email = email;
    }

    @Override
    public String toString() {
        return "UserPrinciple(" +
                "email=" + email +
                " username=" + getUsername() +
                " role=" + getAuthorities() +
                ')';
    }
}

