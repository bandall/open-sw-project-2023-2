package com.jwt.web.controller.advice;

import com.jwt.web.controller.json.ApiResponseJson;
import com.jwt.web.controller.json.ResponseStatusCode;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@Slf4j
@RestControllerAdvice
public class ExceptionAdvice {

    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    @ExceptionHandler(RuntimeException.class)
    public ApiResponseJson handleRuntimeException(RuntimeException e) {
        log.error("", e);
        return new ApiResponseJson(HttpStatus.INTERNAL_SERVER_ERROR, ResponseStatusCode.SERVER_ERROR,
                Map.of("errMsg", "서버에 오류가 발생했습니다."));
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler({IllegalArgumentException.class, IllegalStateException.class})
    public ApiResponseJson handleBadRequestException(Exception e) {
        return new ApiResponseJson(HttpStatus.BAD_REQUEST, ResponseStatusCode.WRONG_PARAMETER,
                Map.of("errMsg", e.getMessage()));
    }

}
