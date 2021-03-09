package de.konfidas.ttc.exceptions;

public class ParsingException extends TtcException{
    public ParsingException(String message, Exception reason) {
        super(message, reason);
    }
    public ParsingException(String message) {
        super(message, null);
    }
}
