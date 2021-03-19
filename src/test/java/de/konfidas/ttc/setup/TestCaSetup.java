

package de.konfidas.ttc.setup;

import org.bouncycastle.operator.OperatorCreationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.apache.commons.io.FileUtils;

import static org.junit.Assert.fail;



public class TestCaSetup {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);

    @Test
    public void setupCA()  {
        String exportDir = "";
        try {
            exportDir =  Files.createTempDirectory("ca_export").toString();
        }
        catch (IOException e) {
            e.printStackTrace();
        }

        String exportPathCACertificate =  Paths.get(exportDir, "root-cert.cer").toString();
        String exportPathSubCACertificate =  Paths.get(exportDir, "subca-cert.cer").toString();
        String exportPathClientCertificate =  Paths.get(exportDir, "client-cert.cer").toString();
        String exportPathCAKey =  Paths.get(exportDir, "root-cert.pfx").toString();
        String exportPathSubCAKey =  Paths.get(exportDir, "subca-cert.pfx").toString();
        String exportPathClientKey =  Paths.get(exportDir, "client-cert.pfx").toString();

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

        File removeDir = new File(exportDir);
        try {
            FileUtils.forceDelete(removeDir); //delete directory
        }
        catch (IOException e) {
            logger.info("Exportverzeichnis konnte nicht gelöscht werden");
            fail();
        }

        logger.info("Exportverzeichnis wird wieder gelöscht");
        logger.info("============================================================================");

    }
}
