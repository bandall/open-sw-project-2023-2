package com.jwt.domin.login;

import com.jwt.domin.member.Member;
import com.jwt.domin.member.MemberRepository;
import com.jwt.domin.member.Role;
import com.jwt.web.controller.dto.MemberCreateDto;
import java.util.regex.Pattern;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class LoginService {

    private static final String PASSWORD_REGEX = "^(?=.*[A-Za-z])(?=.*\\d)(?=.*[$@$!%*#?&])[A-Za-z\\d$@$!%*#?&]{8,}$";
    private static final Pattern PASSWORD_PATTERN = Pattern.compile(PASSWORD_REGEX);
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    public Member createMember(MemberCreateDto memberCreateDto) {
        checkPasswordStrength(memberCreateDto.getPassword());

        if (memberRepository.existsByEmail(memberCreateDto.getEmail())) {
            log.info("이미 등록된 이메일={}", memberCreateDto.getEmail());
            throw new IllegalStateException("이미 등록된 이메일입니다.");
        }

        Member member = Member.builder()
                .email(memberCreateDto.getEmail())
                .password(passwordEncoder.encode(memberCreateDto.getPassword()))
                .username(memberCreateDto.getUsername())
                .role(Role.ROLE_USER).build();

        return memberRepository.save(member);
    }

    private void checkPasswordStrength(String password) {
        if (PASSWORD_PATTERN.matcher(password).matches()) {
            return;
        }

        log.info("비밀번호 정책 미달");
        throw new IllegalArgumentException("비밀번호는 최소 8자리에 영어, 숫자, 특수문자를 포함해야 합니다.");
    }

}

