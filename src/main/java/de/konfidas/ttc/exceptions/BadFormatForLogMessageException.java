package de.konfidas.ttc.exceptions;

/**
 * Diese Exception zeigt eine Fehlerhafte LogMessage an. Sie wird geworfen, wenn eine LogMessage nicht geparst werden kann.
 */
public class BadFormatForLogMessageException extends TtcException {

    public BadFormatForLogMessageException(String message) {
        super(message, null);
    }
    public BadFormatForLogMessageException(String message, Throwable cause) {
        super(message, cause);
    }

}
