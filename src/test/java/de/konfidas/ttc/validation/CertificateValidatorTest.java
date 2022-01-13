package de.konfidas.ttc.validation;

import de.konfidas.ttc.exceptions.CertificateLoadException;
import de.konfidas.ttc.utilities.CertificateHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.security.Security;
import java.security.cert.CertificateExpiredException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

public class CertificateValidatorTest {

    @BeforeEach
    public void initialize() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testLoadExpiredCertificate_ShouldThrowException() throws CertificateLoadException, IOException {
        try {
            CertificateHelper.loadCertificate(new File("testdata" + File.separator + "certificates" + File.separator + "outdated_certificate" + File.separator + "sub.cer"));
            fail("The expected CertificateExpiredException was not thrown.");
        } catch (CertificateLoadException e) {
            assertEquals(CertificateExpiredException.class, e.getCause().getClass());
        }
    }

}
