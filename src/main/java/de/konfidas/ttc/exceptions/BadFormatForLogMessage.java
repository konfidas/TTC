package de.konfidas.ttc.exceptions;

/**
 * Diese Exception zeigt eine Fehlerhafte LogMessage an. Sie wird geworfen, wenn eine LogMessage nicht geparst werden kann.
 */
public class BadFormatForLogMessage extends Exception {
    private String message;

    public BadFormatForLogMessage(String message) {
        this.message = message;
    }

    @Override
    public String getMessage() {
        return message;
    }
}
