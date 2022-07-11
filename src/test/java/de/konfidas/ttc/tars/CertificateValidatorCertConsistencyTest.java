package de.konfidas.ttc.tars;

import de.konfidas.ttc.exceptions.CertificateInconsistentToFilenameException;
import de.konfidas.ttc.utilities.CertificateHelper;
import de.konfidas.ttc.validation.CertificateFileNameValidator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.security.Security;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.fail;


public class CertificateValidatorCertConsistencyTest {
    final static File good1File = new File("testdata/certificates/good1.cer");
    final static File broken1File = new File("testdata/certificates/123456789.cer");

    @BeforeEach
    public void initialize() {
        Security.addProvider(new BouncyCastleProvider());
    }


    @Test
    public void testOk() throws Exception {
        X509Certificate good1Cert = CertificateHelper.loadCertificate(good1File.toPath());

        CertificateFileNameValidator.validateCertificateAgainstFilename(good1Cert, "ADB6400083CDCB70BDBEEBFA86DEA3951394567DFE693D3C849C787947715F5C");
    }


    @Test
    public void testWrongSubject() throws Exception {
        X509Certificate good1Cert = CertificateHelper.loadCertificate(good1File.toPath());
        try {
            CertificateFileNameValidator.validateCertificateAgainstFilename(good1Cert, "00B6400083CDCB70BDBEEBFA86DEA3951394567DFE693D3C849C787947715F5C");
            fail();
        } catch (CertificateInconsistentToFilenameException.FilenameToSubjectMismatchException e) {
            // expected.
        }
    }

    @Test
    public void testWrongPubkey() throws Exception {
        X509Certificate good1Cert = CertificateHelper.loadCertificate(broken1File.toPath());
        try {
//            CertificateFileNameValidator.validateCertificateAgainstFilename(good1Cert, "ADDON1DB43EAF69CAB07036CBF51C4EF78FAD15C532288B1A6D6B7C3E2475ED171766");
            CertificateFileNameValidator.validateCertificateAgainstFilename(good1Cert, "123456789");

            fail();
        } catch (CertificateInconsistentToFilenameException.FilenameToPubKeyMismatchException e) {
            // expected.
        }
    }
}
