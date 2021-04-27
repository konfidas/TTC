package de.konfidas.ttc.exceptions;

import de.konfidas.ttc.messages.LogMessage;

public abstract class LogMessageValidationException extends ValidationException{
    final LogMessage msg;

    public LogMessageValidationException(LogMessage msg){
        this(msg,null);
    }

    public LogMessageValidationException(LogMessage msg, Throwable t){
        super("Validating Log Message "+msg.getFileName()+" failed",t);
        this.msg = msg;
    }

    public LogMessage getLogMessage(){
        return msg;
    }
}
