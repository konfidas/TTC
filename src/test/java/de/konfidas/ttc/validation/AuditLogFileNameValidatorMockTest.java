package de.konfidas.ttc.validation;

import de.konfidas.ttc.exceptions.ValidationException;
import de.konfidas.ttc.messages.AuditLog;
import de.konfidas.ttc.messages.LogMessage;
import de.konfidas.ttc.messages.SystemLog;
import de.konfidas.ttc.messages.logtime.GeneralizedLogTime;
import de.konfidas.ttc.messages.logtime.LogTime;
import de.konfidas.ttc.messages.logtime.UnixLogTime;
import de.konfidas.ttc.messages.logtime.UtcLogTime;
import de.konfidas.ttc.tars.LogMessageArchive;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import static org.junit.Assert.assertTrue;

public class AuditLogFileNameValidatorMockTest {
    ArrayList<LogMessage> messages;

    public AuditLogFileNameValidatorMockTest(){
        messages = new ArrayList<>();
    }

    class TestTar implements LogMessageArchive {
        @Override
        public Map<String, X509Certificate> getIntermediateCertificates() {
            return null;
        }

        @Override
        public Map<String, X509Certificate> getClientCertificates() {
            return null;
        }

        @Override
        public Collection<LogMessage> getLogMessages() {
            return messages;
        }

        @Override
        public Collection<? extends LogMessage> getSortedLogMessages() {
            return messages;
        }
    }
    static class ALM extends LogMessageMock implements AuditLog {
        BigInteger signatureCounter;
        byte[] serial;
        LogTime time;
        String filename;

       ALM(BigInteger signatureCounter, byte[] serial, LogTime time, String filename){
            this.signatureCounter = signatureCounter;
            this.serial = serial;
            this.filename = filename;
            this.time = time;
        }

        @Override
        public LogTime getLogTime() {
            return time;
        }

        @Override
        public BigInteger getSignatureCounter() {
            return signatureCounter;
        }

        @Override
        public byte[] getSerialNumber() {
            return serial;
        }

        @Override
        public String getFileName() {
            return filename;
        }
    }

    @Before
    public void clean(){
        messages.clear();
    }

    @Test
    public void testEmpty(){
        AuditLogFileNameValidator validator = new AuditLogFileNameValidator();
        LogMessageArchive tar = new TestTar();
        Collection<ValidationException> r = validator.validate(tar);

        assertTrue(r.isEmpty());
    }

    @Test
    public void testEmptyFileName(){
        AuditLogFileNameValidator validator = new AuditLogFileNameValidator();
        LogMessageArchive tar = new TestTar();

        messages.add(new ALM(BigInteger.ONE, new byte[]{}, null, ""));

        Collection<ValidationException> r = validator.validate(tar);

        assertTrue(r.size() == 6);
    }


    @Test
    public void testExampleFromTr() throws ParseException {
        AuditLogFileNameValidator validator = new AuditLogFileNameValidator();
        LogMessageArchive tar = new TestTar();

        messages.add(new ALM(BigInteger.valueOf(1853),
                 new byte[]{},
                 new UnixLogTime(1543565694),
                "Unixt_1543565694_Sig-1853_Log-Aud_Fc-1.log"));

        Collection<ValidationException> r = validator.validate(tar);

        assertTrue(r.isEmpty());
    }


}
