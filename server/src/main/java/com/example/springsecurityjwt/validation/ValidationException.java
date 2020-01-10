package com.example.springsecurityjwt.validation;

import org.springframework.validation.FieldError;

import java.util.ArrayList;
import java.util.List;

public class ValidationException extends RuntimeException{

    private List<FieldError> errors = new ArrayList<>();

    public ValidationException(List<FieldError> errors) {
        this.errors = errors;
    }

    public ValidationException(String message, List<FieldError> errors) {
        super(message);
        this.errors = errors;
    }

    public ValidationException(String message, Throwable cause, List<FieldError> errors) {
        super(message, cause);
        this.errors = errors;
    }

    public List<FieldError> getErrors(){
        return errors;
    }
}
