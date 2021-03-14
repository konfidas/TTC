package de.konfidas.ttc.exceptions;

public class LogMessageVerificationException extends TtcException{

    public LogMessageVerificationException(String message) {
        super(message, null);
    }
    public LogMessageVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}
