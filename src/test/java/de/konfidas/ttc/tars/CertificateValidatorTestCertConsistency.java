package de.konfidas.ttc.tars;

import de.konfidas.ttc.utilities.CertificateHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.security.Security;
import java.security.cert.X509Certificate;

import static org.junit.Assert.fail;

public class CertificateValidatorTestCertConsistency {
    final static File good1File  = new File("testdata/certificates/good1.cer");
    final static File broken1File  = new File("testdata/certificates/broken1.cer");

    @Before
    public void initialize() {
        Security.addProvider(new BouncyCastleProvider());
    }


    @Test
    public void testOk() throws Exception{
        X509Certificate good1Cert = CertificateHelper.loadCertificate(good1File.toPath());
        CertificateValidator.validateCertificateAgainstFilename(good1Cert, "ADB6400083CDCB70BDBEEBFA86DEA3951394567DFE693D3C849C787947715F5C");
    }


    @Test
    public void testWrongSubject() throws Exception{
        X509Certificate good1Cert = CertificateHelper.loadCertificate(good1File.toPath());
        try {
            CertificateValidator.validateCertificateAgainstFilename(good1Cert, "00B6400083CDCB70BDBEEBFA86DEA3951394567DFE693D3C849C787947715F5C");
            fail();
        }catch(CertificateValidator.FilenameToSubjectMismatchException e){
            // expected.
        }
    }


    // FIXME: need cert
    @Test
    public void testWrongPubkey() throws Exception{
        X509Certificate good1Cert = CertificateHelper.loadCertificate(broken1File.toPath());
        try {
            CertificateValidator.validateCertificateAgainstFilename(good1Cert, "");
            fail();
        }catch(CertificateValidator.FilenameToPubKeyMismatchException e){
            // expected.
        }
    }
}
