package de.konfidas.ttc.exceptions;

import de.konfidas.ttc.messages.LogMessage;

public class LogMessageException extends Exception{
    LogMessage logMessage;
    protected LogMessageException(String message, Throwable cause, LogMessage logMessage){
        super(message, cause);
        this.logMessage = logMessage;
    }

    @Override
    public String toString(){
        if(this.getCause() != null) {
            return getMessage() + ", cause: " + getCause().toString();
        }else{
            return getMessage();
        }
    }
}
