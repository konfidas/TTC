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
public class LogMessageArchiveTestParsingSuccessfully {
    final static Logger logger = LoggerFactory.getLogger(LogMessageArchiveTestParsingSuccessfully.class);
    final static File correctTarFiles = new File("D:\\testdata\\tars\\"); // TODO: as soon as we have publish-able test data, point path to it.

    File file;

    @Before
    public void initialize() {
        Security.addProvider(new BouncyCastleProvider());
    }


    @Parameterized.Parameters
    public static Collection filesToTest(){

        logger.info("checking for Tars in "+correctTarFiles.getName());
        if(null == correctTarFiles || !correctTarFiles.isDirectory()){
            logger.error("not a directory.");
            return Collections.EMPTY_LIST;
        }


        return Arrays.asList(correctTarFiles.listFiles());
    }


    public LogMessageArchiveTestParsingSuccessfully(File file){
        this.file = file;
    }

    @Test
    public void parse() throws IOException{
        logger.info("");
        logger.info("============================================================================");
        logger.info("testing tar file {}:", file.getName());

        LogMessageArchive tar  = new LogMessageArchive(this.file);
        tar.verify(null,false);
    }
}
