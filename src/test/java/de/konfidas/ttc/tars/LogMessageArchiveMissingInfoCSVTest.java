package de.konfidas.ttc.tars;

import de.konfidas.ttc.exceptions.BadFormatForTARException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;


public class LogMessageArchiveMissingInfoCSVTest {

    @BeforeEach
    public void initialize() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void parseTARWithMissingInfoCSV_shouldThrowException() throws Exception {

        try {
            new LogMessageArchiveImplementation(new File(File.separator + "testdata" + File.separator + "negative" + File.separator + "testdata_no_info_csv" + File.separator + "testdata_no_info_csv.tar"));
            fail("The expected Exception was not thrown when parsing a broken TAR file.");
        } catch (BadFormatForTARException e) {
            assertTrue(true);
        }
    }
}
