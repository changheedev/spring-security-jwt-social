package com.example.springsecurityjwt.advice;

import com.example.springsecurityjwt.authentication.AuthenticationFailedException;
import com.example.springsecurityjwt.authentication.UnauthorizedException;
import com.example.springsecurityjwt.validation.ValidationException;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@Slf4j
@ControllerAdvice
@RestController
public class CommonExceptionAdvice {

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(value = {ValidationException.class})
    public ErrorResponse validationExceptionHandler(ValidationException e) {
        log.error(e.getMessage(), e);
        List<FieldError> errors = e.getErrors();
        return new ErrorResponse(400, e.getMessage(), errors);
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(value = {IllegalArgumentException.class, IllegalStateException.class})
    public ErrorResponse badRequestHandler(Exception e) {
        log.error(e.getMessage(), e);
        return new ErrorResponse(400, e.getMessage());
    }

    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    @ExceptionHandler(value = {AuthenticationFailedException.class, UnauthorizedException.class})
    public ErrorResponse unauthorizedHandler(Exception e) {
        log.error(e.getMessage(), e);
        return new ErrorResponse(401, e.getMessage());
    }

    @ResponseStatus(HttpStatus.METHOD_NOT_ALLOWED)
    @ExceptionHandler(value = {HttpRequestMethodNotSupportedException.class})
    public ErrorResponse methodNotAllowedHandler(Exception e) {
        log.error(e.getMessage(), e);
        return new ErrorResponse(405, "지원하지 않는 API 입니다.");
    }

    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    @ExceptionHandler(value = {Exception.class})
    public ErrorResponse internalServerErrorHandler(Exception e) {
        log.error(e.getMessage(), e);
        return new ErrorResponse(500, "Internal server error");
    }

    @Getter
    @NoArgsConstructor
    public static class ErrorResponse {
        private int code;
        private String message;
        private List<FieldError> errors;

        public ErrorResponse(int code, String message) {
            this.code = code;
            this.message = message;
        }

        public ErrorResponse(int code, String message, List<FieldError> errors) {
            this.code = code;
            this.message = message;
            this.errors = errors;
        }
    }
}
