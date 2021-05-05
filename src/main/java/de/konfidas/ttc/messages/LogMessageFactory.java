package de.konfidas.ttc.messages;

import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.messages.systemlogs.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public class LogMessageFactory {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);

    public static LogMessageImplementation createLogMessage(File file) throws BadFormatForLogMessageException, IOException {
        return createLogMessage(file.getName(), Files.readAllBytes(file.toPath()));
    }


    public static LogMessageImplementation createLogMessage(String fileName, byte[] content) throws BadFormatForLogMessageException {

        if (fileName.matches("^(Gent_|Unixt_|Utc_).+_Sig-\\d+_Log-.+(Start|Update|Finish)_Client-.+log")) {
            logger.debug("{} scheint eine TransactionLog zu sein. Starte Verarbeitung.", fileName);
           return new TransactionLogMessage(content, fileName);
        }

        if (fileName.matches("^(Gent_|Unixt_|Utc_)\\d+_Sig-\\d+_Log-Sys_unblockUser.+log")) {
            logger.debug("{} scheint ein unblockUser systemLog zu sein. Starte Verarbeitung ", fileName);
            return new UnblockUserSystemLogMessage(content, fileName);
        }

        if (fileName.matches("^(Gent_|Unixt_|Utc_)\\d+_Sig-\\d+_Log-Sys_authenticateUser.+log")) {
            logger.debug("{} scheint ein unblockUser systemLog zu sein. Starte Verarbeitung ", fileName);
            return new AuthenticateUserSystemLogMessage(content, fileName);
        }

        if (fileName.matches("^(Gent_|Unixt_|Utc_)\\d+_Sig-\\d+_Log-Sys_authenticateSmaersAdmin.+log")) {
            logger.debug("{} scheint ein unblockUser systemLog zu sein. Starte Verarbeitung ", fileName);
            return new AuthenticateSmaersAdminSystemLogMessage(content, fileName);
        }

        if (fileName.matches("^(Gent_|Unixt_|Utc_)\\d+_Sig-\\d+_Log-Sys_registerClient.+log")) {
            logger.debug("{} scheint ein unblockUser systemLog zu sein. Starte Verarbeitung ", fileName);
            return new RegisterClientLogMessage(content, fileName);
        }

        if (fileName.matches("^(Gent_|Unixt_|Utc_)\\d+_Sig-\\d+_Log-Sys_deregisterClient.+log")) {
            logger.debug("{} scheint ein unblockUser systemLog zu sein. Starte Verarbeitung ", fileName);
            return new DeregisterClientLogMessage(content, fileName);
        }

        if (fileName.matches("^(Gent_|Unixt_|Utc_)\\d+_Sig-\\d+_Log-Sys_startAudit.+log")) {
            logger.debug("{} scheint ein startAudit systemLog zu sein. Starte Verarbeitung ", fileName);
            return new StartAuditSystemLogMessage(content, fileName);
        }

        if (fileName.matches("^(Gent_|Unixt_|Utc_)\\d+_Sig-\\d+_Log-Sys_initialize.+log")) {
            logger.debug("{} scheint ein initialize systemLog zu sein. Starte Verarbeitung ", fileName);
            return new InitializeSystemLogMessage(content, fileName);
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
