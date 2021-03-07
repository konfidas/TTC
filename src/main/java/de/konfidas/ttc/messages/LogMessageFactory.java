package de.konfidas.ttc.messages;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LogMessageFactory {
    final static Logger logger = LoggerFactory.getLogger(LogMessageFactory.class);

    public static LogMessage createLogMessage(String individualFileName, byte[] content){

        if (individualFileName.matches("^(Gent_|Unixt_|Utc_).+_Sig-\\d+_Log-.+(Start|Update|Finish)_Client-.+log")) {
            logger.info("{} scheint eine TransactionLog zu sein. Starte Verarbeitung.", individualFileName);
           return new TransactionLogMessage(content, individualFileName);
        }

        if (individualFileName.matches("^(Gent_|Unixt_|Utc_)\\d+_Sig-\\d+_Log-Sys.+log")) {
            logger.info("{} scheint ein systemLog zu sein. Starte Verarbeitung ", individualFileName);
            return new SystemLogMessage(content, individualFileName);
        }

        if (individualFileName.matches("^(Gent_|Unixt_|Utc_)\\d+_Sig-\\d+_Log-Aud.+log")) {
            logger.info("{} scheint ein auditLog zu sein. Starte Verarbeitung.", individualFileName);
            return new AuditLogMessage(content, individualFileName);
        }

        return null;
    }
}
