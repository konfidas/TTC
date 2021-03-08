package de.konfidas.ttc.messages;

import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public class LogMessageFactory {
    final static Logger logger = LoggerFactory.getLogger(LogMessageFactory.class);

    public static LogMessage createLogMessage(File file) throws BadFormatForLogMessageException, IOException {
        return createLogMessage(file.getName(), Files.readAllBytes(file.toPath()));
    }


    public static LogMessage createLogMessage(String fileName, byte[] content) throws BadFormatForLogMessageException {

        if (fileName.matches("^(Gent_|Unixt_|Utc_).+_Sig-\\d+_Log-.+(Start|Update|Finish)_Client-.+log")) {
            logger.info("{} scheint eine TransactionLog zu sein. Starte Verarbeitung.", fileName);
           return new TransactionLogMessage(content, fileName);
        }

        if (fileName.matches("^(Gent_|Unixt_|Utc_)\\d+_Sig-\\d+_Log-Sys.+log")) {
            logger.info("{} scheint ein systemLog zu sein. Starte Verarbeitung ", fileName);
            return new SystemLogMessage(content, fileName);
        }

        if (fileName.matches("^(Gent_|Unixt_|Utc_)\\d+_Sig-\\d+_Log-Aud.+log")) {
            logger.info("{} scheint ein auditLog zu sein. Starte Verarbeitung.", fileName);
            return new AuditLogMessage(content, fileName);
        }

        throw new BadFormatForLogMessageException("Filename "+fileName+" does not declare Log Message Type");
    }
}
