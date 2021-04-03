package de.konfidas.ttc.messages;

import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.setup.TestCaseBasisWithCA;
import de.konfidas.ttc.utilities.oid;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.junit.Test;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Random;


import static junit.framework.TestCase.fail;

public class TestAuditLogMessages extends TestCaseBasisWithCA {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);


    @Test
    public void validAuditLogMessage() throws LogMessageBuilder.TestLogMessageCreationError, BadFormatForLogMessageException { ;
        AuditLogMessageBuilder auditLogMessageBuilder = new AuditLogMessageBuilder();
        byte[] auditMessage = auditLogMessageBuilder.prepare()
                                .calculateDTBS()
                                .sign(getClientCertKeyPair().getPrivate())
                                .build()
                                .finalizeMessage();


        String filename = auditLogMessageBuilder.getFilename();
        AuditLogMessage auditLogMessage = new AuditLogMessage(auditMessage, filename);
    }



    @Test
    public void validAuditLogMessageWithSeAuditDataWithExtendedLength() throws LogMessageBuilder.TestLogMessageCreationError, BadFormatForLogMessageException { ;
        AuditLogMessageBuilder auditLogMessageBuilder = new AuditLogMessageBuilder();
         auditLogMessageBuilder.prepare();



        byte[] longSeAuditData = new byte[2048];
        new Random().nextBytes(longSeAuditData);
        DEROctetString seAuditDataAsASN1WithExtendedLength = new DEROctetString(longSeAuditData);

        byte[] auditMessage =    auditLogMessageBuilder.calculateDTBS()
                                .sign(getClientCertKeyPair().getPrivate())
                                .build()
                                .finalizeMessage();


        String filename = auditLogMessageBuilder.getFilename();

        AuditLogMessage auditLogMessage = new AuditLogMessage(auditMessage, filename);
    }

    @Test
    public void wrongVersion() throws LogMessageBuilder.TestLogMessageCreationError, BadFormatForLogMessageException {

        try{
        AuditLogMessageBuilder auditLogMessageBuilder = new AuditLogMessageBuilder();
        // Falsche Version setzen
            byte[] auditMessage = auditLogMessageBuilder.setVersion(3)
                                .prepare()
                                .calculateDTBS()
                                .sign(getClientCertKeyPair().getPrivate())
                                .build()
                                .finalizeMessage();

        String filename = auditLogMessageBuilder.getFilename();

        AuditLogMessage auditLogMessage = new AuditLogMessage(auditMessage, filename);}
        catch (LogMessage.LogMessageParsingException  e){
            //expected
            return;
        }
        fail();
    }

    @ParameterizedTest
    @EnumSource(value = oid.class, names = {"id_SE_API_transaction_log", "id_SE_API_system_log"})
    public void auditLogMessageWithWromgCertifiedDataType(oid wrongCertifiedDataType) throws LogMessageBuilder.TestLogMessageCreationError, BadFormatForLogMessageException {
        try{

        AuditLogMessageBuilder auditLogMessageBuilder = new AuditLogMessageBuilder();
        // CertifiedDataType falsch setzen

            byte[] auditMessage = auditLogMessageBuilder
                                .prepare()
                                .setCertifiedDataTypeAsASN1(new ASN1ObjectIdentifier(wrongCertifiedDataType.getReadable()))
                                .calculateDTBS()
                                .sign(getClientCertKeyPair().getPrivate())
                                .build()
                                .finalizeMessage();

        String filename = auditLogMessageBuilder.getFilename();

        AuditLogMessage auditLogMessage = new AuditLogMessage(auditMessage, filename);}
        catch (LogMessage.LogMessageParsingException  e){
            //expected
            return;
        }
        fail();
    }

    @Test
    public void auditLogMessageWithCertifiedData() throws LogMessageBuilder.TestLogMessageCreationError, BadFormatForLogMessageException {
        try{

        AuditLogMessageBuilder auditLogMessageBuilder = new AuditLogMessageBuilder();
        // CertifiedData setzen

            byte[] auditMessage = auditLogMessageBuilder
                                .prepare()
                                .setCertifiedDataAsASN1(new DEROctetString(new byte[5]))
                                .calculateDTBS()
                                .sign(getClientCertKeyPair().getPrivate())
                                .build()
                                .finalizeMessage();

        String filename = auditLogMessageBuilder.getFilename();
        AuditLogMessage auditLogMessage = new AuditLogMessage(auditMessage, filename);}
        catch (LogMessage.LogMessageParsingException  e){
            //expected
            // Hier müssen wir aber sicherstellen, dass der Test aus dem richtigen Grund fehlschlägt
            if (e.getMessage().contains("AuditLogMessage mit certifiedData")) return;
            else fail();
        }
        fail();
    }
    

    @ParameterizedTest
    @ValueSource(strings = {"setVersionAsASN1ToNull","setSerialNumberAsASN1ToNull","setSeAuditDataAsASN1ToNull","setSignatureValueAsASN1ToNull"})
    public void elementIsMissing(String functionToSetElementToNull) throws LogMessageBuilder.TestLogMessageCreationError, BadFormatForLogMessageException {

        try{
            Method setElementToNullMethod = AuditLogMessageBuilder.class.getMethod(functionToSetElementToNull);
            AuditLogMessageBuilder operationsInstance = new AuditLogMessageBuilder();

            AuditLogMessageBuilder auditLogMessageBuilder = new AuditLogMessageBuilder();

            auditLogMessageBuilder
                    .prepare()
                    .calculateDTBS()
                    .sign(getClientCertKeyPair().getPrivate());


            //Ein Element wird entfernt
            setElementToNullMethod.invoke(auditLogMessageBuilder);

            byte[] auditMessage =  auditLogMessageBuilder.build()
                                  .finalizeMessage();

            String filename = auditLogMessageBuilder.getFilename();

            AuditLogMessage auditLogMessage = new AuditLogMessage(auditMessage, filename);
        }

        catch (LogMessage.LogMessageParsingException e){
            //expected
            return;

        } catch (IllegalAccessException| NoSuchMethodException| InvocationTargetException e) {
            e.printStackTrace();
        }
        fail();
    }


}
