package de.konfidas.ttc.messages;

import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.setup.TestCaseBasisWithCA;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

import static junit.framework.TestCase.fail;

public class TestAuditLogMessages extends TestCaseBasisWithCA {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);


    @Test
    public void validAuditLogMessage() throws TestLogMessageFactory.TestLogMessageCreationError, BadFormatForLogMessageException { ;
        TestAuditLogMessageFactory auditLogMessageFactory = new TestAuditLogMessageFactory();
        auditLogMessageFactory.prepare();

        auditLogMessageFactory.calculateDTBS();
        auditLogMessageFactory.sign(getClientCertKeyPair().getPrivate());


        auditLogMessageFactory.build();

        byte[] auditMessage = auditLogMessageFactory.finalizeMessage();
        String filename = auditLogMessageFactory.getFilename();

        AuditLogMessage auditLogMessage = new AuditLogMessage(auditMessage, filename);
    }

    @Test
    public void wrongVersion() throws TestLogMessageFactory.TestLogMessageCreationError, BadFormatForLogMessageException {

        try{
        TestAuditLogMessageFactory auditLogMessageFactory = new TestAuditLogMessageFactory();
        // Falsche Version setzen
        auditLogMessageFactory.setVersion(3);

        auditLogMessageFactory.prepare();

        auditLogMessageFactory.calculateDTBS();
        auditLogMessageFactory.sign(getClientCertKeyPair().getPrivate());

        auditLogMessageFactory.build();

        byte[] auditMessage = auditLogMessageFactory.finalizeMessage();
        String filename = auditLogMessageFactory.getFilename();

        AuditLogMessage auditLogMessage = new AuditLogMessage(auditMessage, filename);}
        catch (LogMessage.LogMessageParsingException e){
            //expected
            return;
        }
        fail();
    }

    @Test
    public void versionElementIsMissing() throws TestLogMessageFactory.TestLogMessageCreationError, BadFormatForLogMessageException {

        try{
            TestAuditLogMessageFactory auditLogMessageFactory = new TestAuditLogMessageFactory();


            auditLogMessageFactory.prepare();
            // Das Versionselement wird entfernt
            auditLogMessageFactory.setVersionAsASN1ToNull();

            auditLogMessageFactory.calculateDTBS();
            auditLogMessageFactory.sign(getClientCertKeyPair().getPrivate());

            auditLogMessageFactory.build();

            byte[] auditMessage = auditLogMessageFactory.finalizeMessage();
            String filename = auditLogMessageFactory.getFilename();

            AuditLogMessage auditLogMessage = new AuditLogMessage(auditMessage, filename);
        }
        catch (LogMessage.LogMessageParsingException e){
            //expected
            return;

        }
        fail();
    }
}
