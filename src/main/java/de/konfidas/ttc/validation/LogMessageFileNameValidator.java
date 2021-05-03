package de.konfidas.ttc.validation;

import de.konfidas.ttc.exceptions.LogMessageValidationException;
import de.konfidas.ttc.exceptions.ValidationException;
import de.konfidas.ttc.messages.LogMessage;
import de.konfidas.ttc.messages.logtime.GeneralizedLogTime;
import de.konfidas.ttc.messages.logtime.LogTime;
import de.konfidas.ttc.messages.logtime.UnixLogTime;
import de.konfidas.ttc.messages.logtime.UtcLogTime;
import de.konfidas.ttc.tars.LogMessageArchive;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1UTCTime;

import java.math.BigInteger;
import java.text.ParseException;
import java.util.Collection;
import java.util.LinkedList;


// This class implements the checks, which were requested in https://github.com/konfidas/TTC/issues/7

/**
 * BSI-TR03151 specifies the filenames of log messages in exported TARs. This Validator validates, the filenames
 * according to the specification.
 *
 * Section 5.1.2.1 on Page 56 specifies for transaction logs:
 *
 * DATE-FORMAT_DATE_Sig-SIGNATURE-COUNTER_LOG_No-TRANSACTION_TYPE_Client-CLIENT-ID_Fc-FILE-COUNTER.log
 *
 * Section 5.1.2.2 on Page 57 specifies for system logs:
 *
 * DATE-FORMAT_DATE_Sig-SIGNATURE-COUNTER_LOG_TYPE_Fc-FILE-COUNTER.log
 *
 * and Section 5.1.2.3 on Page 59 specifies for audit logs:
 *
 * DATE-FORMAT_DATE_Sig-SIGNATURE-COUNTER_LOG_Fc-FILE-COUNTER.log
 */
public class LogMessageFileNameValidator implements Validator{
    @Override
    public Collection<ValidationException> validate(LogMessageArchive tar) {
        LinkedList<ValidationException> result = new LinkedList<>();

        for(LogMessage msg : tar.getLogMessages()){
            result.addAll(checkMsg(msg));
        }

        return result;
    }

    Collection<ValidationException> checkMsg(LogMessage msg) {
        LinkedList<ValidationException> result = new LinkedList<>();

        String[] components = msg.getFileName().split("_");

        if(!(components.length == getNumExpectedComponents())){
            result.add(new MissingComponentException(msg));
        }

        if(components.length >= 1){
            result.addAll(checkLogTime(components[0], msg));
        }

        if(components.length >= 2){
            result.addAll(checkSigCounter(components[1], msg));
        }

        return result;
    }

    protected int getNumExpectedComponents() {
        return 4;
    }

    Collection<ValidationException> checkSigCounter(String component, LogMessage msg) {
        LinkedList<ValidationException> result = new LinkedList<>();
        String[] sigCounter = component.split("-");

        if(!(sigCounter.length == 2)){
            result.add(new BadFormattedMissingSigTagException(msg));
            return result;
        }

        if(!sigCounter[0].equals("Sig")){
            result.add(new MissingSigTagException(msg));
        }

        if(!msg.getSignatureCounter().equals(new BigInteger(sigCounter[1]))){
            result.add(new DifferentSigCounterException(msg, msg.getSignatureCounter()));
        }

        return result;
    }


    Collection<ValidationException> checkLogTime(String component, LogMessage msg) {
        LinkedList<ValidationException> result = new LinkedList<>();
        String[] logTime = component.split("-");

        if(!(logTime.length == 2)){
            result.add(new WrongLogTimeInNameException(msg));
        }

        LogTime timeFromFileName = null;

        switch (logTime[0]){
            case "Unixt":
                if(msg.getLogTime().getType() != LogTime.Type.UNIX){
                    result.add(new DifferentLogTimeTypeException(msg, LogTime.Type.UNIX));
                } else {
                    timeFromFileName = new UnixLogTime(Long.valueOf(logTime[1]));
                }
                break;
            case "Utc":
                if(msg.getLogTime().getType() != LogTime.Type.UTC) {
                    result.add(new DifferentLogTimeTypeException(msg, LogTime.Type.UTC));
                } else {
                    try {
                        timeFromFileName = new UtcLogTime(new ASN1UTCTime(logTime[1]));
                    } catch(ParseException e){
                        result.add(new WrongLogTimeInNameException(msg, e));
                    }
                }
                break;
            case "Gent":
                if(msg.getLogTime().getType() != LogTime.Type.GENERALIZED) {
                    result.add(new DifferentLogTimeTypeException(msg, LogTime.Type.GENERALIZED));
                } else {
                    try {
                        timeFromFileName = new GeneralizedLogTime(new ASN1GeneralizedTime(logTime[1]));
                    } catch(ParseException e){
                        result.add(new WrongLogTimeInNameException(msg, e));
                    }
                }
                break;
            default: result.add(new DifferentLogTimeTypeException(msg, null));
        }

        if(null != timeFromFileName){
            if(timeFromFileName.getTime() != msg.getLogTime().getTime()){
                result.add(new DifferentLogTimeException(msg, timeFromFileName));
            }
        }else{
            result.add(new WrongLogTimeInNameException(msg));
        }
        return result;
    }

    public static class LogMessageFileNameValidationException extends LogMessageValidationException{
        public LogMessageFileNameValidationException(LogMessage msg, Throwable t) {
            super(msg,t);
        }
    }

    public static class WrongLogTimeInNameException extends LogMessageFileNameValidationException{
        public WrongLogTimeInNameException(LogMessage msg, Throwable t) {
            super(msg,t );
        }
        public WrongLogTimeInNameException(LogMessage msg) {
            this(msg,null);
        }
    }

    public static class DifferentLogTimeException extends WrongLogTimeInNameException {
        final LogTime expected;

        public DifferentLogTimeException(LogMessage msg, LogTime expected) {
            super(msg);
            this.expected = expected;
        }
    }

    public static class DifferentSigCounterException extends LogMessageFileNameValidationException {
        final BigInteger expected;

        public DifferentSigCounterException(LogMessage msg, BigInteger expected) {
            super(msg,null);
            this.expected = expected;
        }
    }

    public static class MissingSigTagException extends LogMessageFileNameValidationException {
        public MissingSigTagException(LogMessage msg) {
            super(msg, null);
        }
    }

    public static class BadFormattedMissingSigTagException extends LogMessageFileNameValidationException {
        public BadFormattedMissingSigTagException(LogMessage msg) {
            super(msg, null);
        }
    }

    public static class DifferentLogTimeTypeException extends WrongLogTimeInNameException {
        final LogTime.Type expectedType;

        public DifferentLogTimeTypeException(LogMessage msg, LogTime.Type expectedType) {
            super(msg);
            this.expectedType = expectedType;
        }
    }

    public static class MissingComponentException extends LogMessageFileNameValidationException {
        public MissingComponentException(LogMessage msg) {
            super(msg, null);
        }
    }
}
