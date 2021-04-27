package de.konfidas.ttc.exceptions;

public abstract class ValidationException extends TtcException {
    public ValidationException(String message, Throwable cause){
        super(message, cause);
    }
}
