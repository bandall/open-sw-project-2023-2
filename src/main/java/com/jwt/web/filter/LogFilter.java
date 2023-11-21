package com.jwt.web.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.util.PatternMatchUtils;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * 로그 ID를 남기기 위한 로깅 필터 필터 최상단에 존재한다.
 */
@Slf4j
@Component
@Order(SecurityProperties.DEFAULT_FILTER_ORDER - 2)
public class LogFilter extends OncePerRequestFilter {
    public static final String TRACE_ID = "traceId";
    public static final String[] noFilterUrl = {"/error", "/favicon.ico"};
    private static final String LOG_START_FORMAT = "[REQUEST URI : {}, METHOD : {}]";
    private static final String LOG_END_FORMAT = "Response Time = {}ms";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String requestURI = request.getRequestURI();
        String uuid = UUID.randomUUID().toString().substring(24, 36);

        if (isNoLoggingUrl(requestURI)) {
            filterChain.doFilter(request, response);
            MDC.clear();
            return;
        }

        long startTime = startLogging(request, requestURI, uuid);

        filterChain.doFilter(request, response);

        endLogging(startTime);
    }

    private boolean isNoLoggingUrl(String requestURI) {
        return PatternMatchUtils.simpleMatch(noFilterUrl, requestURI);
    }

    private long startLogging(HttpServletRequest request, String requestURI, String uuid) {
        MDC.put(TRACE_ID, uuid);
        long startTime = System.currentTimeMillis();
        log.info(LOG_START_FORMAT, requestURI, request.getMethod());
        return startTime;
    }

    private void endLogging(long startTime) {
        long totalTime = System.currentTimeMillis() - startTime;
        log.info(LOG_END_FORMAT, totalTime);
        MDC.clear();
    }
}
