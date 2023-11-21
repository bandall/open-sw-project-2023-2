package com.jwt.web.controller;

import com.jwt.domin.login.LoginService;
import com.jwt.domin.member.Member;
import com.jwt.web.controller.dto.MemberCreateDto;
import com.jwt.web.controller.json.ApiResponseJson;
import jakarta.validation.Valid;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.validation.BindingResult;
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
}
