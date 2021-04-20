package de.konfidas.ttc.validation;

import de.konfidas.ttc.exceptions.BadFormatForTARException;
import de.konfidas.ttc.tars.LogMessageArchive;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
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
public class SignatureCounterValidatorTest {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    final static File tarFiles = new File("testdata/positive");

    File file;

    @Before
    public void initialize() {
        Security.addProvider(new BouncyCastleProvider());
    }


    @Parameterized.Parameters
    public static Collection filesToTest() {

        logger.info("checking for Tars in " + tarFiles.getName());
        if (null == tarFiles || !tarFiles.isDirectory()) {
            fail("not a directory.");

            return Collections.EMPTY_LIST;
        }

        return Arrays.asList(tarFiles.listFiles());
    }

    public SignatureCounterValidatorTest(File file) {
            this.file = file;
        }

    @Test
    public void parse() throws IOException {
        logger.info("");
        logger.info("============================================================================");
        logger.info("testing tar file {}:", file.getName());

        try {
            SignatureCounterValidator validator = new SignatureCounterValidator();


            LogMessageArchive tar = new LogMessageArchive(this.file);

            Collection<ValidationException>  errors = validator.validate(tar);

            assert(errors.size() == 1); // which is true for the one archive, which we have!

        }
        catch (IOException | BadFormatForTARException e) {
            fail();
        }
    }


}
