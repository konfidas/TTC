package de.konfidas.ttc.messages;

import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.messages.systemlogs.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Locale;
import java.util.ResourceBundle;

public class LogMessageFactory {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);

    static Locale locale = new Locale("de", "DE"); //NON-NLS
    static ResourceBundle properties = ResourceBundle.getBundle("ttc",locale);//NON-NLS

    public static LogMessageImplementation createLogMessage(File file) throws BadFormatForLogMessageException, IOException {
        return createLogMessage(file.getName(), Files.readAllBytes(file.toPath()));
    }


    public static LogMessageImplementation createLogMessage(String fileName, byte[] content) throws BadFormatForLogMessageException {

        if (fileName.matches("^(Gent_|Unixt_|Utc_).+_Sig-\\d+_Log-.+(Start|Update|Finish)_Client-.+log")) {
            logger.debug("{} seems to be a TransactionLog. Processing it now. ", fileName);//NON-NLS
           return new TransactionLogMessage(content, fileName);
        }

        if (fileName.matches("^(Gent_|Unixt_|Utc_)\\d+_Sig-\\d+_Log-Sys_unblockUser.+log")) {
            logger.debug("{} seems to be an unblockUser systemLog. Processing it now. ", fileName);//NON-NLS
            return new UnblockUserSystemLogMessage(content, fileName);
        }

        if (fileName.matches("^(Gent_|Unixt_|Utc_)\\d+_Sig-\\d+_Log-Sys_authenticateUser.+log")) {
            logger.debug("{} seems to be an authenitcateUser systemLog. Processing it now. ", fileName);//NON-NLS
            return new AuthenticateUserSystemLogMessage(content, fileName);
        }

        if (fileName.matches("^(Gent_|Unixt_|Utc_)\\d+_Sig-\\d+_Log-Sys_authenticateSmaersAdmin.+log")) {
            logger.debug("{} seems to be an authenticateSmaersAdmin systemLog. Processing it now. ", fileName);//NON-NLS
            return new AuthenticateSmaersAdminSystemLogMessage(content, fileName);
        }

        if (fileName.matches("^(Gent_|Unixt_|Utc_)\\d+_Sig-\\d+_Log-Sys_registerClient.+log")) {
            logger.debug("{} seems to be a registerClient systemLog. Processing it now.", fileName);//NON-NLS
            return new RegisterClientLogMessage(content, fileName);
        }

        if (fileName.matches("^(Gent_|Unixt_|Utc_)\\d+_Sig-\\d+_Log-Sys_deregisterClient.+log")) {
            logger.debug("{} seems to be a deregisterClient systemLog. Processing it now.", fileName);//NON-NLS
            return new DeregisterClientLogMessage(content, fileName);
        }

        if (fileName.matches("^(Gent_|Unixt_|Utc_)\\d+_Sig-\\d+_Log-Sys_startAudit.+log")) {
            logger.debug("{} seems to be a startAudit systemLog. Processing it now.", fileName);//NON-NLS
            return new StartAuditSystemLogMessage(content, fileName);
        }

        if (fileName.matches("^(Gent_|Unixt_|Utc_)\\d+_Sig-\\d+_Log-Sys_initialize.+log")) {
            logger.debug("{} seems to be a initialize systemLog. Processing it now.", fileName);//NON-NLS
            return new InitializeSystemLogMessage(content, fileName);
        }

        if (fileName.matches("^(Gent_|Unixt_|Utc_)\\d+_Sig-\\d+_Log-Sys_updateTime.+log")) {
            logger.debug("{} seems to be an upateTime log. Processing it now.", fileName);//NON-NLS
            return new UpdateTimeSystemLogMessage(content, fileName);
        }

//        if (fileName.matches("^(Gent_|Unixt_|Utc_)\\d+_Sig-\\d+_Log-Sys.+log")) {
//            logger.debug("{} scheint ein systemLog zu sein. Starte Verarbeitung ", fileName);
//            return new SystemLogMessage(content, fileName);
//        }

        if (fileName.matches("^(Gent_|Unixt_|Utc_)\\d+_Sig-\\d+_Log-Aud.+log")) {
            logger.debug("{} seems to be an auditLog. Processing it now.", fileName);//NON-NLS
            return new AuditLogMessage(content, fileName);
        }

        throw new BadFormatForLogMessageException(String.format(properties.getString("de.konfidas.ttc.messages.fileNameUnknownTypeOfLogMessages"),fileName));
    }
}
