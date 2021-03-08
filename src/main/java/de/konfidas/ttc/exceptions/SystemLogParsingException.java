package de.konfidas.ttc.exceptions;

public class SystemLogParsingException extends BadFormatForLogMessageException{
    public SystemLogParsingException(String message) { super(message); }
    public SystemLogParsingException(String message, Exception reason) {
        super(message, reason);
    }

}
