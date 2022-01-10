package de.konfidas.ttc.validation;

import de.konfidas.ttc.errors.TtcError;
import de.konfidas.ttc.exceptions.CertificateLoadException;
import de.konfidas.ttc.exceptions.ValidationException;
import de.konfidas.ttc.messages.LogMessage;
import de.konfidas.ttc.tars.LogMessageArchive;
import de.konfidas.ttc.utilities.CertificateHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.provider.Arguments;
import java.util.stream.Stream;

import java.io.File;
import java.io.IOException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;


public class CertificateValidatorTest {
    Map<String, X509Certificate> client = new HashMap<>();
    Map<String, X509Certificate> intermediates = new HashMap<>();
    Collection<X509Certificate> trusted = new ArrayList<>();

    class TestTarMock implements LogMessageArchive {

        @Override
        public Map<String, X509Certificate> getIntermediateCertificates() {
            return intermediates;
        }

        @Override
        public Map<String, X509Certificate> getClientCertificates() {
            return client;
        }

        @Override
        public Collection<LogMessage> getLogMessages() {
            return null;
        }

        @Override
        public Collection<? extends LogMessage> getSortedLogMessages() {
            return null;
        }

        @Override
        public ArrayList<TtcError> getAllErrors() {
            return new ArrayList<TtcError>();
        }

        @Override
        public String getFileName() {
            return "";
        }
    }

    @BeforeAll
    public static void setup(){
        Security.addProvider(new BouncyCastleProvider());
    }

    @BeforeEach
    public void clean(){
        client.clear();
        intermediates.clear();
        trusted.clear();
    }

    @Test
    public void testDTrustChain() throws CertificateLoadException, IOException {
        client.put("client",CertificateHelper.loadCertificate(new File("testdata/certificates/dtrust/client.cer")));
        intermediates.put("intermediate",CertificateHelper.loadCertificate(new File("testdata/certificates/dtrust/sub.cer")));
        trusted.add(CertificateHelper.loadCertificate(new File("testdata/certificates/dtrust/root.cer")));

        TestTarMock tar = new TestTarMock();

        CertificateValidator validator = new CertificateValidator(trusted);
        validator.setEnableRevocationChecking(false);

        Collection<ValidationException> errors = validator.validate(tar).getValidationErrors();

        for(ValidationException e : errors){
            e.printStackTrace();
        }

        assertTrue(errors.isEmpty());
    }

    @Test
    public void testDTrustChain_missingTrustAnchor() throws CertificateLoadException, IOException {
        client.put("client",CertificateHelper.loadCertificate(new File("testdata/certificates/dtrust/client.cer")));
        intermediates.put("intermediate",CertificateHelper.loadCertificate(new File("testdata/certificates/dtrust/sub.cer")));
        // trusted.add(CertificateHelper.loadCertificate(new File("testdata/certificates/dtrust/root.cer")));

        TestTarMock tar = new TestTarMock();

        CertificateValidator validator = new CertificateValidator(trusted);
        validator.setEnableRevocationChecking(false);

        Collection<ValidationException> errors = validator.validate(tar).getValidationErrors();

        assertFalse(errors.isEmpty());
    }


    @Test
    public void testDTrustChain_missingSubCa() throws CertificateLoadException, IOException {
        client.put("client",CertificateHelper.loadCertificate(new File("testdata/certificates/dtrust/client.cer")));
        //intermediates.put("intermediate",CertificateHelper.loadCertificate(new File("testdata/certificates/dtrust/sub.cer")));
         trusted.add(CertificateHelper.loadCertificate(new File("testdata/certificates/dtrust/root.cer")));

        TestTarMock tar = new TestTarMock();

        CertificateValidator validator = new CertificateValidator(trusted);
        validator.setEnableRevocationChecking(false);

        Collection<ValidationException> errors = validator.validate(tar).getValidationErrors();

        assertFalse(errors.isEmpty());
    }

    @Test
    public void testDTrustChain_missingCRL() throws CertificateLoadException, IOException {
        client.put("client",CertificateHelper.loadCertificate(new File("testdata/certificates/dtrust/client.cer")));
        intermediates.put("intermediate",CertificateHelper.loadCertificate(new File("testdata/certificates/dtrust/sub.cer")));
        trusted.add(CertificateHelper.loadCertificate(new File("testdata/certificates/dtrust/root.cer")));

        TestTarMock tar = new TestTarMock();

        CertificateValidator validator = new CertificateValidator(trusted);
        //validator.setEnableRevocationChecking(false);

        Collection<ValidationException> errors = validator.validate(tar).getValidationErrors();

        assertFalse(errors.isEmpty());
    }

}
