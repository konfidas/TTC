package de.konfidas.ttc.tars;

import de.konfidas.ttc.exceptions.BadFormatForTARException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.security.Security;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;


public class LogMessageArchiveTestParsingFailing {

    @BeforeEach
    public void initialize() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void parseBrokenTAR_shouldThrowException() throws Exception {

        try {
            new LogMessageArchiveImplementation(new File("parsingFailing.tar"));
            fail("The expected Exception was not thrown when parsing a broken TAR file.");
        } catch (BadFormatForTARException e) {
            assertTrue(true);
        }
    }
}
