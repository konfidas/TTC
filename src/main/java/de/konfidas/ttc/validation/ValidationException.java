package de.konfidas.ttc.validation;

import de.konfidas.ttc.exceptions.TtcException;
import de.konfidas.ttc.messages.LogMessage;

public abstract class ValidationException extends TtcException {
    public ValidationException(String message, Throwable cause){
        super(message, cause);
    }
}
