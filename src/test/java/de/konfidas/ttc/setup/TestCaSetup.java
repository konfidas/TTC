

package de.konfidas.ttc.setup;

import org.bouncycastle.operator.OperatorCreationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.junit.Test;
import static org.junit.Assert.fail;



public class TestCaSetup {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);

    @Test
    public void setupCA()  {
        String exportPathCACertificate ="/Users/nils/temp/root-cert.cer";
        String exportPathSubCACertificate ="/Users/nils/temp/subca-cert.cer";
        String exportPathClientCertificate = "/Users/nils/temp/client-cert.cer";
        String exportPathCAKey ="/Users/nils/temp/root-cert.pfx";
        String exportPathSubCAKey ="/Users/nils/temp/subca-cert.pfx";
        String exportPathClientKey = "/Users/nils/temp/client-cert.pfx";

        logger.info("============================================================================");
        logger.info("Erzeugung einer CA, Sub-CA und eines Client-Zertifikats");
        logger.info("============================================================================");

        logger.info("Erzeugung und Export der CA");
        TestCAFactory cAFactory = new TestCAFactory();
        try {
            cAFactory.build();
        }
        catch (TestCAFactory.CACreationException | OperatorCreationException e) {
            e.printStackTrace();
            fail();
        }
        try {
            cAFactory.exportCAToFile(exportPathCACertificate,exportPathCAKey);
        }
        catch (TestCAFactory.CANotYetCreatedException | TestCAFactory.CAExportException e) {
            e.printStackTrace();
            fail();
        }
        logger.info("Die CA wurde erstellt und in {} und {} exportiert", exportPathCACertificate,exportPathCAKey);
        logger.info("============================================================================");

        logger.info("Erzeugung und Export der Sub-CA");
        TestSubCAFactory subCAFactory = new TestSubCAFactory(cAFactory.getRootCert(), cAFactory.getRootKeyPair());
        try {
            subCAFactory.build();
        }
        catch (TestSubCAFactory.SubCACreationException | OperatorCreationException e) {
            e.printStackTrace();
            fail();
        }

        try {
            subCAFactory.exportSubCAToFile(exportPathSubCACertificate, exportPathSubCAKey);
        }

        catch (TestSubCAFactory.SubCANotYetCreatedException| TestSubCAFactory.SubCAExportException  e) {
            e.printStackTrace();
            fail();
        }

        logger.info("Die Sub-CA wurde erstellt und in {} und {} exportiert", exportPathSubCACertificate, exportPathSubCAKey);
        logger.info("============================================================================");



        logger.info("Erzeugung und Export eines Client-Zertifikats");
        logger.info("============================================================================");
        TestClientCertificateFactory clientCertFactory = new TestClientCertificateFactory(subCAFactory.getSubCACert(), subCAFactory.getSubCAKeyPair());


        try {
            clientCertFactory.build();
        }
        catch (OperatorCreationException | TestClientCertificateFactory.ClientCertificateCreationException e) {
            e.printStackTrace();
            fail();
        }

        try {
            clientCertFactory.exportClientCertToFile(exportPathClientCertificate,exportPathClientKey);
        }
        catch (TestClientCertificateFactory.ClientCertificateNotYetCreatedException | TestClientCertificateFactory.clientCertExportException e) {
            e.printStackTrace();
            fail();
        }

        logger.info("Ein Client Zertifikat wurde erstellt und in {} und {} exportiert", exportPathClientCertificate, exportPathClientKey);
        logger.info("============================================================================");


    }
}
