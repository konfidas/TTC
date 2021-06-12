
package de.konfidas.ttc.tars;

import de.konfidas.ttc.exceptions.BadFormatForTARException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.security.Security;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

import static org.junit.Assert.fail;

@RunWith(Parameterized.class)
public class LogMessageArchiveTestInconsistentCertificate {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    final static File brokenTarFiles = new File("testdata/negative/inconsistent_certificates/");

    final File file;

    @Before
    public void initialize() {
        Security.addProvider(new BouncyCastleProvider());
    }


    @Parameterized.Parameters
    public static Collection<File> filesToTest() {
        logger.debug("checking for Tars in " + brokenTarFiles.getName());
        if (!brokenTarFiles.isDirectory() || brokenTarFiles.listFiles() == null) {
            return Collections.EMPTY_LIST;
        }
        return Arrays.asList(brokenTarFiles.listFiles());
    }

    public LogMessageArchiveTestInconsistentCertificate(File file) {
        this.file = file;
    }

    //FIXME remove
    @Test
    public void parse() {

    }
//    FIXME
//    @Ignore
//    @Test
//    public void parse() throws IOException {
//        logger.debug("");
//        logger.debug("============================================================================");
//        logger.debug("testing tar file {}:", file.getName());
//
//        try {
//            new LogMessageArchiveImplementation(this.file);
//            fail("Log Message parsing successful, but expected to fail");
//        }
//        catch ( BadFormatForTARException e) {
//            // expected behaviour
//        }
//    }
}
