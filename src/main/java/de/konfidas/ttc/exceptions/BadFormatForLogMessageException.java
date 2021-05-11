package de.konfidas.ttc.exceptions;

import de.konfidas.ttc.messages.LogMessage;

/**
 * Diese Exception zeigt eine Fehlerhafte LogMessage an. Sie wird geworfen, wenn eine LogMessage nicht geparst werden kann.
 */
public class BadFormatForLogMessageException extends LogMessageException {

    public BadFormatForLogMessageException(String message, LogMessage logMessage) {
        super(message, null, logMessage);
    }
    public BadFormatForLogMessageException(String message, Throwable cause, LogMessage logMessage) {
        super(message, cause, logMessage);
    }

}
