package com.example.springsecurityjwt.advice;

import com.example.springsecurityjwt.authentication.AuthenticationProcessException;
import com.example.springsecurityjwt.authentication.UnauthorizedException;
import com.example.springsecurityjwt.authentication.oauth2.OAuth2ProcessException;
import com.example.springsecurityjwt.users.DuplicatedUsernameException;
import com.example.springsecurityjwt.validation.ValidationException;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedList;
import java.util.List;

@Slf4j
@ControllerAdvice
@RestController
public class CommonExceptionAdvice {

    /**
     * Valid 어노테이션이 사용된 파라미터의 바인딩에 실패한 경우
     * 바인딩에 실패한 필드와 메시지 리스트를 만들어 리턴한다.
     *
     * @param e bindingResult 데이터를 포함한 Exception
     * @return
     */
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(value = {ValidationException.class})
    public List<ValidationError> validationExceptionHandler(ValidationException e) {

        List<ValidationError> errors = new LinkedList<>();
        e.getErrors().forEach(error -> {
            errors.add(new ValidationError(error.getField(), error.getDefaultMessage()));
        });

        log.error(e.getMessage(), e);
        return errors;
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(value = {AuthenticationProcessException.class, OAuth2ProcessException.class})
    public ErrorResponse badRequestHandler(Exception e) {
        log.error(e.getMessage(), e);
        return new ErrorResponse(400, "bad_request");
    }

    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    @ExceptionHandler(value = {UnauthorizedException.class})
    public ErrorResponse unauthorizedHandler(Exception e) {
        log.error(e.getMessage(), e);
        return new ErrorResponse(401, "unauthorized_user");
    }

    @ResponseStatus(HttpStatus.METHOD_NOT_ALLOWED)
    @ExceptionHandler(value = {HttpRequestMethodNotSupportedException.class})
    public ErrorResponse methodNotAllowedHandler(Exception e) {
        log.error(e.getMessage(), e);
        return new ErrorResponse(405, "method_not_allowed");
    }

    @ResponseStatus(HttpStatus.CONFLICT)
    @ExceptionHandler(value = {DuplicatedUsernameException.class})
    public ErrorResponse conflictHandler(Exception e) {
        log.error(e.getMessage(), e);
        return new ErrorResponse(409, "resource_conflict");
    }

    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    @ExceptionHandler(value = {Exception.class})
    public ErrorResponse internalServerErrorHandler(Exception e) {
        log.error(e.getMessage(), e);
        return new ErrorResponse(500, "internal_server_error");
    }

    @Getter
    @NoArgsConstructor
    public static class ErrorResponse {
        private int code;
        private String message;

        public ErrorResponse(int code, String message) {
            this.code = code;
            this.message = message;
        }
    }

    @Getter
    @NoArgsConstructor
    public static class ValidationError {
        private String field;
        private String message;

        public ValidationError(String field, String message) {
            this.field = field;
            this.message = message;
        }
    }
}
