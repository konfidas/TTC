package de.konfidas.ttc.messages;

import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.exceptions.LogMessageVerificationException;
import de.konfidas.ttc.setup.TestCaseBasisWithCA;
import org.bouncycastle.asn1.ASN1Integer;
import org.junit.Test;

import java.security.cert.X509Certificate;
import java.util.HashMap;

import static junit.framework.TestCase.fail;

public class TestLogMessageVerifier extends TestCaseBasisWithCA {
    @Test
    public void versionElementIsMissingInDTBS() throws LogMessageBuilder.TestLogMessageCreationError, BadFormatForLogMessageException, LogMessageVerificationException {


            AuditLogMessageBuilder auditLogMessageBuilder = new AuditLogMessageBuilder();

            auditLogMessageBuilder.prepare();
            ASN1Integer tmpVersion = auditLogMessageBuilder.getVersionAsASN1();
            // Das Versionselement wird zwischengespeichert und dann entfernt
            auditLogMessageBuilder.setVersionEncoded(new byte[0])
                    .calculateDTBS()
                    //Das Element wird wieder ergänzt so dass es in der LogMessage vorhanden ist. Die LogMessag hat also eine gütlige Struktur aber ein falsches DTBS.
                    .setVersionAsASN1(tmpVersion)
                    .sign(getClientCertKeyPair().getPrivate())
                    .build();

            byte[] auditMessage = auditLogMessageBuilder.finalizeMessage();

            String filename = auditLogMessageBuilder.getFilename();

            AuditLogMessage auditLogMessage = new AuditLogMessage(auditMessage, filename);

            //Jetzt brauhen wir einen Verifier
            HashMap<String, X509Certificate> certiicates = new HashMap<>();
            certiicates.put(getClientCertificate().getSerialNumber().toString().toUpperCase(),getClientCertificate());


            LogMessageSignatureVerifier verifier = new LogMessageSignatureVerifier(certiicates);
            verifier.verify(auditLogMessage);



        fail();
    }

//    @Test
//    public void logMessageSignedWithWrongCert() throws LogMessageBuilder.TestLogMessageCreationError, BadFormatForLogMessageException {
//
//        try{
//        AuditLogMessageBuilder auditLogMessageBuilder = new AuditLogMessageBuilder();
//        // Die Audit Message wird mit dem CA-Zert statt dem Client-Zert signiert
//            byte[] auditMessage = auditLogMessageBuilder
//                                .prepare()
//                                .calculateDTBS()
//                                .sign(getClientCertKeyPair().getPrivate())
//                                .build()
//                                .finalizeMessage();
//
//        String filename = auditLogMessageBuilder.getFilename();
//
//
//            AuditLogMessage auditLogMessage = new AuditLogMessage(auditMessage, filename);
//
//            //Jetzt brauhen wir einen Verifier
//            HashMap<String, X509Certificate> certificates = new HashMap<String, X509Certificate>();
//            String serial =getClientCertificate().getSerialNumber().toString().toUpperCase();
//            certificates.put(getClientCertificate().getSerialNumber().toString().toUpperCase(),getClientCertificate());
//
//
//            LogMessageSignatureVerifier verifier = new LogMessageSignatureVerifier(certificates);
//            verifier.verify(auditLogMessage);
//
//        }
//        catch (LogMessage.LogMessageParsingException | LogMessageVerificationException  e){
//            //expected
//            return;
//        }
//        fail();
//    }

}
