package de.konfidas.ttc.messages;

import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.messages.systemlogs.UnblockUserSystemLogMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public class LogMessageFactory {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);

    public static LogMessage createLogMessage(File file) throws BadFormatForLogMessageException, IOException {
        return createLogMessage(file.getName(), Files.readAllBytes(file.toPath()));
    }


    public static LogMessage createLogMessage(String fileName, byte[] content) throws BadFormatForLogMessageException {

        if (fileName.matches("^(Gent_|Unixt_|Utc_).+_Sig-\\d+_Log-.+(Start|Update|Finish)_Client-.+log")) {
            logger.debug("{} scheint eine TransactionLog zu sein. Starte Verarbeitung.", fileName);
           return new TransactionLogMessage(content, fileName);
        }

        if (fileName.matches("^(Gent_|Unixt_|Utc_)\\d+_Sig-\\d+_Log-Sys_unblockUser.+log")) {
            logger.debug("{} scheint ein unblockUser systemLog zu sein. Starte Verarbeitung ", fileName);
            return new UnblockUserSystemLogMessage(content, fileName);
        }

//        if (fileName.matches("^(Gent_|Unixt_|Utc_)\\d+_Sig-\\d+_Log-Sys.+log")) {
//            logger.debug("{} scheint ein systemLog zu sein. Starte Verarbeitung ", fileName);
//            return new SystemLogMessage(content, fileName);
//        }

        if (fileName.matches("^(Gent_|Unixt_|Utc_)\\d+_Sig-\\d+_Log-Aud.+log")) {
            logger.debug("{} scheint ein auditLog zu sein. Starte Verarbeitung.", fileName);
            return new AuditLogMessage(content, fileName);
        }

        throw new BadFormatForLogMessageException("Filename "+fileName+" does not declare Log Message Type");
    }
}
