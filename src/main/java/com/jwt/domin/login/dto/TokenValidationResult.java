package com.jwt.domin.login.dto;

import com.jwt.domin.login.jwt.token.TokenStatus;
import com.jwt.domin.login.jwt.token.TokenType;
import io.jsonwebtoken.Claims;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
@AllArgsConstructor
public class TokenValidationResult {
    private TokenStatus tokenStatus;
    private TokenType tokenType;
    private String tokenId;
    private Claims claims;

    public String getEmail() {
        if (claims == null) {
            throw new IllegalStateException("Claim value is null.");
        }

        return claims.getSubject();
    }

    public boolean isValid() {
        return TokenStatus.TOKEN_VALID == this.tokenStatus;
    }
}