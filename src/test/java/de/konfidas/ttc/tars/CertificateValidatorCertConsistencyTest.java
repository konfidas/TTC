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

import static org.junit.jupiter.api.Assertions.assertThrows;


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
        assertThrows(CertificateInconsistentToFilenameException.FilenameToSubjectMismatchException.class, () -> {
            CertificateFileNameValidator.validateCertificateAgainstFilename(good1Cert, "00B6400083CDCB70BDBEEBFA86DEA3951394567DFE693D3C849C787947715F5C");
        });
    }

    @Test
    public void testWrongPubkey() throws Exception {
        X509Certificate good1Cert = CertificateHelper.loadCertificate(broken1File.toPath());

        assertThrows(CertificateInconsistentToFilenameException.FilenameToPubKeyMismatchException.class, () -> {
            CertificateFileNameValidator.validateCertificateAgainstFilename(good1Cert, "123456789");
        });
    }
}
