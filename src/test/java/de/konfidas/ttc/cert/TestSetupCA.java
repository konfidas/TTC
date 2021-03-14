package de.konfidas.ttc.cert;


import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.IOException;



public class TestSetupCA {

    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);


    @Test
    public void setupCA() throws IOException {
        TestCA testCA = new TestCA();

        logger.info("");
        logger.info("============================================================================");

        try {
            int a =0;
            assert (a==0);

        }catch(Exception e){
            // expected exception
        }
    }
}


