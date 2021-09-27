package de.konfidas.ttc.errors;

import de.konfidas.ttc.exceptions.TtcException;

/**
 * Dieser Error zeigt eine Fehlerhafte LogMessage an. Sie wird verwendet, wenn eine LogMessage nicht geparst werden kann.
 */
public class BadFormatForLogMessageError extends TtcError {

    public BadFormatForLogMessageError(String message) {
        super(message, null);
    }
    public BadFormatForLogMessageError(String message, Throwable cause) {
        super(message, cause);
    }

}
