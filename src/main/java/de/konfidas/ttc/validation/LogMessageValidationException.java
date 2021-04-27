package de.konfidas.ttc.validation;

import de.konfidas.ttc.messages.LogMessage;

public abstract class LogMessageValidationException extends ValidationException{
    LogMessage msg;

    LogMessageValidationException(LogMessage msg){
        super("Validating Log Message "+msg.getFileName()+" failed",null);
        this.msg = msg;
    }

    public LogMessage getLogMessage(){
        return msg;
    }
}
