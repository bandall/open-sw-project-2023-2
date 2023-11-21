package com.jwt.domin.login.dto;


import java.util.Date;
import lombok.Builder;
import lombok.Data;
import lombok.ToString;

@Data
@ToString(exclude = {"accessToken"})
public class TokenInfo {

    private String accessToken;

    private Date accessTokenExpireTime;
    private String ownerEmail;
    private String tokenId;

    @Builder
    public TokenInfo(String accessToken, Date accessTokenExpireTime, String ownerEmail, String tokenId) {
        this.accessToken = accessToken;
        this.accessTokenExpireTime = accessTokenExpireTime;
        this.ownerEmail = ownerEmail;
        this.tokenId = tokenId;
    }
}
