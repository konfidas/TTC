package de.konfidas.ttc.validation;

import de.konfidas.ttc.messages.LogMessage;

public abstract class ValidationException extends Exception{
    LogMessage msg;

    ValidationException(LogMessage msg){
        this.msg = msg;
    }

    public LogMessage getLogMessage(){
        return msg;
    }
}
