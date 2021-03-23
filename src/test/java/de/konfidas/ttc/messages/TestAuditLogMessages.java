package de.konfidas.ttc.messages;

import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.setup.TestCaseBasisWithCA;
import org.bouncycastle.asn1.ASN1Integer;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static junit.framework.TestCase.fail;

public class TestAuditLogMessages extends TestCaseBasisWithCA {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);


    @Test
    public void validAuditLogMessage() throws LogMessageBuilder.TestLogMessageCreationError, BadFormatForLogMessageException { ;
        AuditLogMessageBuilder auditLogMessageBuilder = new AuditLogMessageBuilder();
        auditLogMessageBuilder.prepare();

        auditLogMessageBuilder.calculateDTBS();
        auditLogMessageBuilder.sign(getClientCertKeyPair().getPrivate());


        auditLogMessageBuilder.build();

        byte[] auditMessage = auditLogMessageBuilder.finalizeMessage();
        String filename = auditLogMessageBuilder.getFilename();

        AuditLogMessage auditLogMessage = new AuditLogMessage(auditMessage, filename);
    }

    @Test
    public void wrongVersion() throws LogMessageBuilder.TestLogMessageCreationError, BadFormatForLogMessageException {

        try{
        AuditLogMessageBuilder auditLogMessageBuilder = new AuditLogMessageBuilder();
        // Falsche Version setzen
        auditLogMessageBuilder.setVersion(3);

        auditLogMessageBuilder.prepare();

        auditLogMessageBuilder.calculateDTBS();
        auditLogMessageBuilder.sign(getClientCertKeyPair().getPrivate());

        auditLogMessageBuilder.build();

        byte[] auditMessage = auditLogMessageBuilder.finalizeMessage();
        String filename = auditLogMessageBuilder.getFilename();

        AuditLogMessage auditLogMessage = new AuditLogMessage(auditMessage, filename);}
        catch (LogMessage.LogMessageParsingException e){
            //expected
            return;
        }
        fail();
    }

    @Test
    public void versionElementIsMissing() throws LogMessageBuilder.TestLogMessageCreationError, BadFormatForLogMessageException {

        try{
            AuditLogMessageBuilder auditLogMessageBuilder = new AuditLogMessageBuilder();


            auditLogMessageBuilder.prepare();
            // Das Versionselement wird entfernt
            auditLogMessageBuilder.setVersionAsASN1ToNull();

            auditLogMessageBuilder.calculateDTBS();
            auditLogMessageBuilder.sign(getClientCertKeyPair().getPrivate());

            auditLogMessageBuilder.build();

            byte[] auditMessage = auditLogMessageBuilder.finalizeMessage();
            String filename = auditLogMessageBuilder.getFilename();

            AuditLogMessage auditLogMessage = new AuditLogMessage(auditMessage, filename);
        }
        catch (LogMessage.LogMessageParsingException e){
            //expected
            return;

        }
        fail();
    }

    @Test
    @Ignore //Dieser Test schlägt fehl weil die falsche Signatur erst im LogMessageSignatureVerifier auffallen würde.
    public void versionElementIsMissingInDTBS() throws LogMessageBuilder.TestLogMessageCreationError, BadFormatForLogMessageException {

        try{
            AuditLogMessageBuilder auditLogMessageBuilder = new AuditLogMessageBuilder();


            auditLogMessageBuilder.prepare();
            ASN1Integer tmpVersion = auditLogMessageBuilder.getVersionAsASN1();
            // Das Versionselement wird zwischengespeichert und dann entfernt
            auditLogMessageBuilder.setVersionAsASN1ToNull();
            auditLogMessageBuilder.calculateDTBS();

            //Das Element wird wieder ergänzt so dass es in der LogMessage vorhanden ist. Die LogMessag hat also eine gütlige Struktur aber ein falsches DTBS.
            auditLogMessageBuilder.setVersionAsASN1(tmpVersion);
            auditLogMessageBuilder.sign(getClientCertKeyPair().getPrivate());

            auditLogMessageBuilder.build();

            byte[] auditMessage = auditLogMessageBuilder.finalizeMessage();
            String filename = auditLogMessageBuilder.getFilename();

            AuditLogMessage auditLogMessage = new AuditLogMessage(auditMessage, filename);
        }
        catch (LogMessage.LogMessageParsingException e){
            //expected
            return;

        }
        fail();
    }
}
