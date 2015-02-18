package org.springframework.security.jwt.filter.sample.web;

public class HelloResource {

    private String message;

    public HelloResource() {
    }

    public HelloResource(String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
