package com.jwt.web.controller;

import com.jwt.domin.login.LoginService;
import com.jwt.domin.login.dto.TokenInfo;
import com.jwt.domin.member.Member;
import com.jwt.domin.member.UserPrinciple;
import com.jwt.web.controller.dto.MemberCreateDto;
import com.jwt.web.controller.dto.MemberLoginDto;
import com.jwt.web.controller.json.ApiResponseJson;
import jakarta.validation.Valid;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
public class LoginController {

    private final LoginService loginService;

    @PostMapping("/api/account/create")
    public ApiResponseJson createNewAccount(@Valid @RequestBody MemberCreateDto memberCreateDto,
                                            BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            throw new IllegalArgumentException("잘못된 요청입니다.");
        }

        Member member = loginService.createMember(memberCreateDto);
        log.info("Account successfully created with details: {}", member);

        return new ApiResponseJson(HttpStatus.OK, Map.of(
                "email", member.getEmail(),
                "username", member.getUsername()
        ));
    }

    @PostMapping("/api/account/auth")
    public ApiResponseJson authenticateAccountAndIssueToken(@Valid @RequestBody MemberLoginDto memberLoginDto,
                                                            BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            throw new IllegalArgumentException("잘못된 요청입니다.");
        }

        TokenInfo tokenInfoDto = loginService.loginMember(memberLoginDto.getEmail(), memberLoginDto.getPassword());
        log.info("Token issued for account: {}", tokenInfoDto.getTokenId());

        return new ApiResponseJson(HttpStatus.OK, tokenInfoDto);
    }

    @GetMapping("/api/account/userinfo")
    public ApiResponseJson getUserInfo(@AuthenticationPrincipal UserPrinciple userPrinciple) {
        return new ApiResponseJson(HttpStatus.OK, userPrinciple);
    }
}
