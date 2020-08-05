package com.innoq.cookiebasedsessionapp;

public class CookieVerificationFailedException extends RuntimeException {
    public CookieVerificationFailedException(String message) {
        super(message);
    }
}
