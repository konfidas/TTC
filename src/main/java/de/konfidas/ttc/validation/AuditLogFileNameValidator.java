package de.konfidas.ttc.validation;


import de.konfidas.ttc.exceptions.ValidationException;
import de.konfidas.ttc.messages.AuditLog;
import de.konfidas.ttc.messages.LogMessage;


import java.util.LinkedList;


public class AuditLogFileNameValidator extends AbstractLogMessageFileNameValidator{
    final static String LogFormat="Log-Aud";
    
    @Override
    protected String getExpectedLogFormat(){
        return LogFormat;
    }

    @Override
    protected LinkedList<ValidationException> checkMsg(LogMessage msg) {
        if(msg instanceof AuditLog) {
            LinkedList<ValidationException> result = super.checkMsg(msg);

            String[] components = getComponents();

            // TODO

            return result;
        }else{
            return new LinkedList<>();
        }
    }
}
