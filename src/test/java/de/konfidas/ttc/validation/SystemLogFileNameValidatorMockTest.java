package de.konfidas.ttc.validation;

import de.konfidas.ttc.exceptions.ValidationException;
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

public class SystemLogFileNameValidatorMockTest {
    ArrayList<LogMessage> messages;

    public SystemLogFileNameValidatorMockTest(){
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
    static class SLM extends LogMessageMock implements SystemLog {
        BigInteger signatureCounter;
        byte[] serial;
        LogTime time;
        String filename;

       SLM(BigInteger signatureCounter, byte[] serial, LogTime time, String filename){
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
        SystemLogFileNameValidator validator = new SystemLogFileNameValidator();
        LogMessageArchive tar = new TestTar();

        assertTrue(validator.validate(tar).isEmpty());
    }

    @Test
    public void testEmptyFileName(){
        SystemLogFileNameValidator validator = new SystemLogFileNameValidator();
        LogMessageArchive tar = new TestTar();

        messages.add(new SLM(BigInteger.ONE, new byte[]{}, null, ""));

        Collection<ValidationException> r = validator.validate(tar);

        assertTrue(r.size() == 7);
    }


    @Test
    public void testExampleFromTr() throws ParseException {
        SystemLogFileNameValidator validator = new SystemLogFileNameValidator();
        LogMessageArchive tar = new TestTar();

        messages.add(new SLM(BigInteger.valueOf(1743),
                 new byte[]{},
                 new GeneralizedLogTime(new ASN1GeneralizedTime("20181109084236Z")),
                "Gent_20181109084236Z_Sig-1743_Log-Sys_UpdateTime.log"));

        Collection<ValidationException> r = validator.validate(tar);

        assertTrue(r.isEmpty());
    }


    @Test
    public void testExampleFromTr_wrongSigCounter() throws ParseException {
        SystemLogFileNameValidator validator = new SystemLogFileNameValidator();
        LogMessageArchive tar = new TestTar();

        messages.add(new SLM(BigInteger.valueOf(1744),
                new byte[]{},
                new GeneralizedLogTime(new ASN1GeneralizedTime("20181109084236Z")),
                "Gent_20181109084236Z_Sig-1743_Log-Sys_UpdateTime.log"));

        Collection<ValidationException> r = validator.validate(tar);

        assertTrue(r.size() == 1);
        assertTrue(r.stream().findFirst().get() instanceof AbstractLogMessageFileNameValidator.DifferentSigCounterException);
    }

    @Test
    public void testExampleFromTr_wrongSigTag() throws ParseException {
        SystemLogFileNameValidator validator = new SystemLogFileNameValidator();
        LogMessageArchive tar = new TestTar();

        messages.add(new SLM(BigInteger.valueOf(1743),
                new byte[]{},
                new GeneralizedLogTime(new ASN1GeneralizedTime("20181109084236Z")),
                "Gent_20181109084236Z_Tig-1743_Log-Sys_UpdateTime.log"));

        Collection<ValidationException> r = validator.validate(tar);

        assertTrue(r.size() == 1);
        assertTrue(r.stream().findFirst().get() instanceof AbstractLogMessageFileNameValidator.MissingSigTagException);
    }

    @Test
    public void testExampleFromTr_wrongSigTag2() throws ParseException {
        SystemLogFileNameValidator validator = new SystemLogFileNameValidator();
        LogMessageArchive tar = new TestTar();

        messages.add(new SLM(BigInteger.valueOf(1743),
                new byte[]{},
                new GeneralizedLogTime(new ASN1GeneralizedTime("20181109084236Z")),
                "Gent_20181109084236Z_Sig1743_Log-Sys_UpdateTime.log"));

        Collection<ValidationException> r = validator.validate(tar);

        assertTrue(r.size() == 1);
        assertTrue(r.stream().findFirst().get() instanceof AbstractLogMessageFileNameValidator.BadFormattedSigTagException);
    }


    @Test
    public void testExampleFromTr_wrongSyLogTag() throws ParseException {
        SystemLogFileNameValidator validator = new SystemLogFileNameValidator();
        LogMessageArchive tar = new TestTar();

        messages.add(new SLM(BigInteger.valueOf(1743),
                new byte[]{},
                new GeneralizedLogTime(new ASN1GeneralizedTime("20181109084236Z")),
                "Gent_20181109084236Z_Sig-1743_Log-Tra_UpdateTime.log"));

        Collection<ValidationException> r = validator.validate(tar);

        assertTrue(r.size() == 1);
        assertTrue(r.stream().findFirst().get() instanceof AbstractLogMessageFileNameValidator.WrongLogFormatException);
    }


    @Test
    public void testExampleFromTr_wrongTime() throws ParseException {
        SystemLogFileNameValidator validator = new SystemLogFileNameValidator();
        LogMessageArchive tar = new TestTar();

        messages.add(new SLM(BigInteger.valueOf(1743),
                new byte[]{},
                new GeneralizedLogTime(new ASN1GeneralizedTime("20181109084237Z")),
                "Gent_20181109084236Z_Sig-1743_Log-Sys_UpdateTime.log"));

        Collection<ValidationException> r = validator.validate(tar);

        assertTrue(r.size() == 1);
        assertTrue(r.stream().findFirst().get() instanceof AbstractLogMessageFileNameValidator.DifferentLogTimeException);
    }

    @Test
    public void testExampleFromTr_wrongTimeType() throws ParseException {
        SystemLogFileNameValidator validator = new SystemLogFileNameValidator();
        LogMessageArchive tar = new TestTar();

        messages.add(new SLM(BigInteger.valueOf(1743),
                new byte[]{},
                new UtcLogTime(new ASN1UTCTime("181109084236Z")),
                "Gent_20181109084236Z_Sig-1743_Log-Sys_UpdateTime.log"));

        Collection<ValidationException> r = validator.validate(tar);

        assertTrue(r.size() == 1);
        assertTrue(r.stream().findFirst().get() instanceof AbstractLogMessageFileNameValidator.DifferentLogTimeTypeException);
    }


    @Test
    public void testExampleFromTrUtcTime() throws ParseException {
        SystemLogFileNameValidator validator = new SystemLogFileNameValidator();
        LogMessageArchive tar = new TestTar();

        messages.add(new SLM(BigInteger.valueOf(1743),
                new byte[]{},
                new UtcLogTime(new ASN1UTCTime("181109084236Z")),
                "Utc_181109084236Z_Sig-1743_Log-Sys_UpdateTime.log"));

        Collection<ValidationException> r = validator.validate(tar);

        assertTrue(r.isEmpty());
    }


    @Test
    public void testExampleFromTrUtcTime_DifferentTimeType() throws ParseException {
        SystemLogFileNameValidator validator = new SystemLogFileNameValidator();
        LogMessageArchive tar = new TestTar();

        messages.add(new SLM(BigInteger.valueOf(1743),
                new byte[]{},
                new GeneralizedLogTime(new ASN1GeneralizedTime("20181109084236Z")),
                "Utc_181109084236Z_Sig-1743_Log-Sys_UpdateTime.log"));

        Collection<ValidationException> r = validator.validate(tar);

        assertTrue(r.size() == 1);
        assertTrue(r.stream().findFirst().get() instanceof AbstractLogMessageFileNameValidator.DifferentLogTimeTypeException);
    }


    @Test
    public void testExampleFromTr_BrokenTime() throws ParseException {
        SystemLogFileNameValidator validator = new SystemLogFileNameValidator();
        LogMessageArchive tar = new TestTar();

        messages.add(new SLM(BigInteger.valueOf(1743),
                new byte[]{},
                new GeneralizedLogTime(new ASN1GeneralizedTime("20181109084237Z")),
                "Gent_AAA_Sig-1743_Log-Sys_UpdateTime.log"));

        Collection<ValidationException> r = validator.validate(tar);

        assertTrue(r.size() == 1);
        assertTrue(r.stream().findFirst().get() instanceof AbstractLogMessageFileNameValidator.WrongLogTimeInNameException);
    }
    @Test
    public void testExampleFromTr_BrokenUTCTime() throws ParseException {
        SystemLogFileNameValidator validator = new SystemLogFileNameValidator();
        LogMessageArchive tar = new TestTar();

        messages.add(new SLM(BigInteger.valueOf(1743),
                new byte[]{},
                new UtcLogTime(new ASN1UTCTime("181109084236Z")),
                "Utc_AAA_Sig-1743_Log-Sys_UpdateTime.log"));

        Collection<ValidationException> r = validator.validate(tar);

        assertTrue(r.size() == 1);
        assertTrue(r.stream().findFirst().get() instanceof AbstractLogMessageFileNameValidator.WrongLogTimeInNameException);
    }

    @Test
    public void testExampleFromTr_BrokenUnixTime() throws ParseException {
        SystemLogFileNameValidator validator = new SystemLogFileNameValidator();
        LogMessageArchive tar = new TestTar();

        messages.add(new SLM(BigInteger.valueOf(1743),
                new byte[]{},
                new UnixLogTime(123),
                "Unix_AAA_Sig-1743_Log-Sys_UpdateTime.log"));

        Collection<ValidationException> r = validator.validate(tar);

        assertTrue(r.size() == 1);
        assertTrue(r.stream().findFirst().get() instanceof AbstractLogMessageFileNameValidator.WrongLogTimeInNameException);
    }


    @Test
    public void testExampleFromTr_UnixTime() throws ParseException {
        SystemLogFileNameValidator validator = new SystemLogFileNameValidator();
        LogMessageArchive tar = new TestTar();

        messages.add(new SLM(BigInteger.valueOf(1743),
                new byte[]{},
                new UnixLogTime(123),
                "Unix_123_Sig-1743_Log-Sys_UpdateTime.log"));

        Collection<ValidationException> r = validator.validate(tar);
        assertTrue(r.isEmpty());
    }

    @Test
    public void testExampleFromTr_UnixTimeDifferentTypes() throws ParseException {
        SystemLogFileNameValidator validator = new SystemLogFileNameValidator();
        LogMessageArchive tar = new TestTar();

        messages.add(new SLM(BigInteger.valueOf(1743),
                new byte[]{},
                new UtcLogTime(new ASN1UTCTime("181109084236Z")),
                "Unix_123_Sig-1743_Log-Sys_UpdateTime.log"));
        Collection<ValidationException> r = validator.validate(tar);
        assertTrue(r.size() == 2); // Times are also different.
        assertTrue(r.stream().findFirst().get() instanceof AbstractLogMessageFileNameValidator.DifferentLogTimeTypeException);
    }


    @Test
    public void testExampleFromTr_DifferentUnixTime() throws ParseException {
        SystemLogFileNameValidator validator = new SystemLogFileNameValidator();
        LogMessageArchive tar = new TestTar();

        messages.add(new SLM(BigInteger.valueOf(1743),
                new byte[]{},
                new UnixLogTime(124),
                "Unix_123_Sig-1743_Log-Sys_UpdateTime.log"));

        Collection<ValidationException> r = validator.validate(tar);
        assertTrue(r.size() == 1);
        assertTrue(r.stream().findFirst().get() instanceof AbstractLogMessageFileNameValidator.DifferentLogTimeException);
    }
}
