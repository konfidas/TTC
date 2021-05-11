package de.konfidas.ttc.validation;


import de.konfidas.ttc.exceptions.ValidationException;
import de.konfidas.ttc.messages.LogMessage;
import de.konfidas.ttc.messages.SystemLogMessage;
import de.konfidas.ttc.messages.TransactionLogMessage;

import java.math.BigInteger;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;


public class SystemLogFileNameValidator extends AbstractLogMessageFileNameValidator{
    final static String LogFormat="Log-Sys";
    
    @Override
    protected String getExpectedLogFormat(){
        return LogFormat;
    }

    @Override
    protected Collection<? extends ValidationException> checkLogFormat(String component, LogMessage msg) {
        if(!LogFormat.equals(component)){
            return Collections.singleton(new WrongLogFormatException(LogFormat, component, msg));
        }
        return null;
    }

    @Override
    protected LinkedList<ValidationException> checkMsg(LogMessage msg) {
        if(msg instanceof SystemLogMessage) {
            LinkedList<ValidationException> result = super.checkMsg(msg);

            String[] components = msg.getFileName().split("_");

            if(components.length >= 5) {
                // FIXME:
                // ((SystemLogMessage) msg).
            }else{
                result.add(new MissingComponentException(msg));
            }
            return result;
        }else{
            return new LinkedList<>();
        }
    }
}
