package de.konfidas.ttc.validation;


import de.konfidas.ttc.exceptions.ValidationException;
import de.konfidas.ttc.messages.LogMessage;
import de.konfidas.ttc.messages.SystemLog;
import java.util.LinkedList;


public class SystemLogFileNameValidator extends AbstractLogMessageFileNameValidator{
    final static String LogFormat="Log-Sys";
    
    @Override
    protected String getExpectedLogFormat(){
        return LogFormat;
    }

    @Override
    protected LinkedList<ValidationException> checkMsg(LogMessage msg) {
        if(msg instanceof SystemLog) {
            LinkedList<ValidationException> result = super.checkMsg(msg);

            String[] components = getComponents();

            if(components.length >= 5) {
                // TODO: compare this component to the content of the system log message.
            }else{
                result.add(new MissingComponentException(msg));
            }
            return result;
        }else{
            return new LinkedList<>();
        }
    }
}
