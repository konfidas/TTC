package de.konfidas.ttc.validation;

import de.konfidas.ttc.exceptions.LogMessageValidationException;
import de.konfidas.ttc.exceptions.ValidationException;
import de.konfidas.ttc.messages.LogMessage;
import de.konfidas.ttc.messages.SystemLogMessage;
import de.konfidas.ttc.messages.logtime.LogTime;
import de.konfidas.ttc.tars.LogMessageArchive;
import org.apache.commons.codec.binary.Hex;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;

public class TimeStampValidator implements Validator{
    final HashMap<String, LogTime> lastLogTime;

    public TimeStampValidator(){
        lastLogTime = new HashMap<>();
    }

    @Override
    public Collection<ValidationException> validate(LogMessageArchive tar) {
        LinkedList<ValidationException> result = new LinkedList<>();

        ArrayList<LogMessage> messages = new ArrayList<>(tar.getLogMessages());
        messages.sort(new LogMessage.SignatureCounterComparator());

        String serial;

        for(LogMessage msg : messages) {
            serial = Hex.encodeHexString(msg.getSerialNumber());

            if(lastLogTime.containsKey(serial)){
                if(!lastLogTime.get(serial).wasNotAfter(msg.getLogTime())){
                    result.add(new LogTimeMissMatchException(msg, lastLogTime.get(serial)));
                }
                lastLogTime.replace(serial, msg.getLogTime());

            }else{
                lastLogTime.put(serial, msg.getLogTime());
            }


            if(msg instanceof SystemLogMessage){
                SystemLogMessage sysLog = (SystemLogMessage) msg;

                // FIXME: check for updateTime event and update
                // lastLogTime(serial) accordingly!
            }


        }
        return result;
    }

    static class LogTimeMissMatchException extends LogMessageValidationException {
        final LogTime previousLogTime;

        LogTimeMissMatchException(LogMessage msg, LogTime previousLogTime){
            super(msg);
            this.previousLogTime = previousLogTime;
        }
    }
}
