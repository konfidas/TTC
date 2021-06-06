package de.konfidas.ttc.exceptions;


import de.konfidas.ttc.messages.LogMessage;

import java.util.Locale;
import java.util.ResourceBundle;

public abstract class LogMessageValidationException extends ValidationException{
    final LogMessage msg;

    static Locale locale = new Locale("de", "DE");
    static ResourceBundle properties = ResourceBundle.getBundle("ttc",locale);

    public LogMessageValidationException(LogMessage msg){
        this(msg,null);
    }

    public LogMessageValidationException(LogMessage msg, Throwable t){
        super(String.format(properties.getString("de.konfidas.ttc.exceptions.validationOfLogMessageFailed"), msg.getFileName()),t);
        this.msg = msg;
    }

    public LogMessage getLogMessage(){
        return msg;
    }
}
