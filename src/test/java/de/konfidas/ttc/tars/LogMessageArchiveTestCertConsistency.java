package de.konfidas.ttc.tars;

import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.nio.file.Files;
import java.security.Security;
import java.security.cert.X509Certificate;

import static org.junit.Assert.fail;

public class LogMessageArchiveTestCertConsistency {
    final static File good1File  = new File("testdata/certificates/good1.cer");
    final static File broken1File  = new File("testdata/certificates/broken1.cer");

    @Before
    public void initialize() {
        Security.addProvider(new BouncyCastleProvider());
    }


    @Test
    public void testOk() throws Exception{
        byte[] certFileContent = Files.readAllBytes(good1File.toPath());
        X509Certificate good1Cert = LogMessageArchive.loadCertificate(certFileContent);
        LogMessageArchive.validateCertificateAgainstFilename(good1Cert, "ADB6400083CDCB70BDBEEBFA86DEA3951394567DFE693D3C849C787947715F5C");
    }


    @Test
    public void testWrongSubject() throws Exception{
        byte[] certFileContent = Files.readAllBytes(good1File.toPath());
        X509Certificate good1Cert = LogMessageArchive.loadCertificate(certFileContent);
        try {
            LogMessageArchive.validateCertificateAgainstFilename(good1Cert, "00B6400083CDCB70BDBEEBFA86DEA3951394567DFE693D3C849C787947715F5C");
            fail();
        }catch(LogMessageArchive.FilenameToSubjectMismatchException e){
            // expected.
        }
    }


    // FIXME: need cert
    @Test
    public void testWrongPubkey() throws Exception{
        byte[] certFileContent = Files.readAllBytes(broken1File.toPath());
        X509Certificate good1Cert = LogMessageArchive.loadCertificate(certFileContent);
        try {
            LogMessageArchive.validateCertificateAgainstFilename(good1Cert, "Daniel Heldt");
            fail();
        }catch(LogMessageArchive.FilenameToPubKeyMismatchException e){
            // expected.
        }
    }
}
