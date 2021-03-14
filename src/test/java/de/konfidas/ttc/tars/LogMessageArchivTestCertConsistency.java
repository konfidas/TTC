package de.konfidas.ttc.tars;

import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.nio.file.Files;
import java.security.Security;
import java.security.cert.X509Certificate;

public class LogMessageArchivTestCertConsistency {
    final static File good1File  = new File("testdata/certificates/good1.cer");
    final static String good1Name = "ADB6400083CDCB70BDBEEBFA86DEA3951394567DFE693D3C849C787947715F5C";

    @Before
    public void initialize() {
        Security.addProvider(new BouncyCastleProvider());
    }


    @Test
    public void test() throws Exception{
        byte[] certFileContent = Files.readAllBytes(good1File.toPath());
        X509Certificate good1Cert = LogMessageArchive.loadCertificate(certFileContent);
        LogMessageArchive.validateCertificateAgainstFilename(good1Cert, good1Name);
    }
}
