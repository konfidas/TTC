package de.konfidas.ttc.exceptions;

public class ParsingException extends TtcException{
    public ParsingException(String message, Throwable cause) {
        super(message, cause);
    }
    public ParsingException(String message) {
        super(message, null);
    }
}
