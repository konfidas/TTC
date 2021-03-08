package de.konfidas.ttc.tars;

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

@RunWith(Parameterized.class)
public class LogMessageArchiveTest {
    final static Logger logger = LoggerFactory.getLogger(LogMessageArchiveTest.class);
    final static File correctTarFiles = new File("D:\\testdata"); // TODO: as soon as we have publish-able test data, point path to it.

    File file;

    @Before
    public void initialize() {
        Security.addProvider(new BouncyCastleProvider());
    }


    @Parameterized.Parameters
    public static Collection tarFilesToTest(){

        if(null == correctTarFiles || !correctTarFiles.isDirectory()){
            return Collections.EMPTY_LIST;
        }

        return Arrays.asList(correctTarFiles.listFiles());
    }


    public LogMessageArchiveTest(File file){
        this.file = file;
    }

    @Test
    public void parse() throws IOException{
        logger.info("");
        logger.info("============================================================================");
        logger.info("testing file {}:", file.getName());

        LogMessageArchive tar  = new LogMessageArchive(this.file);
        
    }
}
