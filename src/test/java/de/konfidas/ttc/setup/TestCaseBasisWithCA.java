package de.konfidas.ttc.setup;

import org.bouncycastle.operator.OperatorCreationException;
import org.junit.BeforeClass;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import static org.junit.Assert.fail;


public class TestCaseBasisWithCA {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    protected static Path exportDir;
    static {
        try {
            exportDir = Files.createTempDirectory("testCaseBasis");
        } catch (IOException e) {
            e.printStackTrace();
            fail();
        }
    }
    protected static String exportPathCACertificate = Paths.get(exportDir.toString(), "root-cert.cer").toString();
    protected static String exportPathSubCACertificate = Paths.get(exportDir.toString(), "subca-cert.cer").toString();
    protected static String exportPathClientCertificate = Paths.get(exportDir.toString(), "client-cert.cer").toString();
    protected static String exportPathCAKey = Paths.get(exportDir.toString(), "root-cert.pfx").toString();
    protected static String exportPathSubCAKey = Paths.get(exportDir.toString(), "subca-cert.pfx").toString();
    protected static String exportPathClientKey = Paths.get(exportDir.toString(), "client-cert.pfx").toString();



   static Boolean setupComplete = false;
   static  X509Certificate rootCACertificate;
   static X509Certificate subCACertificate;
   static X509Certificate clientCertificate;
   static   KeyPair rootCAKeyPair;
   static   KeyPair subCAKeyPair;
    static KeyPair clientCertKeyPair;

    public static X509Certificate getRootCACertificate() {
        if (!setupComplete) setupCA();
        return rootCACertificate;
    }

    public static X509Certificate getSubCACertificate() {
        if (!setupComplete) setupCA();
        return subCACertificate;
    }

    public static X509Certificate getClientCertificate() {
        if (!setupComplete) setupCA();
        return clientCertificate;
    }

    public static KeyPair getRootCAKeyPair() {
        if (!setupComplete) setupCA();
        return rootCAKeyPair;
    }

    public static KeyPair getSubCAKeyPair() {
        if (!setupComplete) setupCA();
        return subCAKeyPair;
    }

    public static KeyPair getClientCertKeyPair() {
        if (!setupComplete) setupCA();
        return clientCertKeyPair;
    }

    @BeforeClass
    public static void setupCA()  {

        logger.debug("============================================================================");
        logger.debug("Erzeugung einer CA, Sub-CA und eines Client-Zertifikats");
        logger.debug("============================================================================");

        logger.debug("Erzeugung und Export der CA");
        TestCAFactory cAFactory = new TestCAFactory();
        try {
            cAFactory.build();
        }
        catch (TestCAFactory.CACreationException | OperatorCreationException e) {
            e.printStackTrace();
            fail();
        }

        rootCACertificate = cAFactory.getRootCert();
        rootCAKeyPair = cAFactory.getRootKeyPair();

        logger.debug("Die CA wurde erstellt");
        logger.debug("============================================================================");

        logger.debug("Erzeugung und Export der Sub-CA");
        TestSubCAFactory subCAFactory = new TestSubCAFactory(cAFactory.getRootCert(), cAFactory.getRootKeyPair());
        try {
            subCAFactory.build();
        }
        catch (TestSubCAFactory.SubCACreationException | OperatorCreationException e) {
            e.printStackTrace();
            fail();
        }

        subCACertificate = subCAFactory.getSubCACert();
        subCAKeyPair = subCAFactory.getSubCAKeyPair();

        logger.debug("Die Sub-CA wurde erstellt");
        logger.debug("============================================================================");



        logger.debug("Erzeugung und Export eines Client-Zertifikats");
        logger.debug("============================================================================");
        TestClientCertificateFactory clientCertFactory = new TestClientCertificateFactory(subCAFactory.getSubCACert(), subCAFactory.getSubCAKeyPair());


        try {
            clientCertFactory.build();
        }
        catch (OperatorCreationException | TestClientCertificateFactory.ClientCertificateCreationException e) {
            e.printStackTrace();
            fail();
        }

        clientCertificate = clientCertFactory.getClientCert();
        clientCertKeyPair = clientCertFactory.getClientKeyPair();
        logger.debug("Ein Client Zertifikat wurde erstellt");
        logger.debug("============================================================================");

        setupComplete = true;

    }
//
//    @Test
//    public static void setupCAAndExport()  {
//
//        logger.debug("============================================================================");
//        logger.debug("Erzeugung einer CA, Sub-CA und eines Client-Zertifikats");
//        logger.debug("============================================================================");
//
//        logger.debug("Erzeugung und Export der CA");
//        TestCAFactory cAFactory = new TestCAFactory();
//        try {
//            cAFactory.build();
//        }
//        catch (TestCAFactory.CACreationException | OperatorCreationException e) {
//            e.printStackTrace();
//            fail();
//        }
//        try {
//            cAFactory.exportCAToFile(exportPathCACertificate,exportPathCAKey);
//        }
//        catch (TestCAFactory.CANotYetCreatedException | TestCAFactory.CAExportException e) {
//            e.printStackTrace();
//            fail();
//        }
//        logger.debug("Die CA wurde erstellt und in {} und {} exportiert", exportPathCACertificate,exportPathCAKey);
//        logger.debug("============================================================================");
//
//        logger.debug("Erzeugung und Export der Sub-CA");
//        TestSubCAFactory subCAFactory = new TestSubCAFactory(cAFactory.getRootCert(), cAFactory.getRootKeyPair());
//        try {
//            subCAFactory.build();
//        }
//        catch (TestSubCAFactory.SubCACreationException | OperatorCreationException e) {
//            e.printStackTrace();
//            fail();
//        }
//
//        try {
//            subCAFactory.exportSubCAToFile(exportPathSubCACertificate, exportPathSubCAKey);
//        }
//
//        catch (TestSubCAFactory.SubCANotYetCreatedException| TestSubCAFactory.SubCAExportException  e) {
//            e.printStackTrace();
//            fail();
//        }
//
//        logger.debug("Die Sub-CA wurde erstellt und in {} und {} exportiert", exportPathSubCACertificate, exportPathSubCAKey);
//        logger.debug("============================================================================");
//
//
//
//        logger.debug("Erzeugung und Export eines Client-Zertifikats");
//        logger.debug("============================================================================");
//        TestClientCertificateFactory clientCertFactory = new TestClientCertificateFactory(subCAFactory.getSubCACert(), subCAFactory.getSubCAKeyPair());
//
//
//        try {
//            clientCertFactory.build();
//        }
//        catch (OperatorCreationException | TestClientCertificateFactory.ClientCertificateCreationException e) {
//            e.printStackTrace();
//            fail();
//        }
//
//        try {
//            clientCertFactory.exportClientCertToFile(exportPathClientCertificate,exportPathClientKey);
//        }
//        catch (TestClientCertificateFactory.ClientCertificateNotYetCreatedException | TestClientCertificateFactory.clientCertExportException e) {
//            e.printStackTrace();
//            fail();
//        }
//
//        logger.debug("Ein Client Zertifikat wurde erstellt und in {} und {} exportiert", exportPathClientCertificate, exportPathClientKey);
//        logger.debug("============================================================================");
//
//
//
//    }
//
//    @AfterClass
//    public static void cleanup() {
//
//        File removeDir = new File(exportDir.toString());
//        try {
//            FileUtils.forceDelete(removeDir); //delete directory
//        } catch (IOException e) {
//            logger.debug("Exportverzeichnis konnte nicht gelöscht werden");
//            fail();
//        }
//
//        logger.debug("Exportverzeichnis wird gelöscht");
//        logger.debug("============================================================================");
//    }

//    @Test
//    public void testLogMessagens()  {
//        String exportDir = System.getenv("TMP_FOLDER");
//
//        if (exportDir == null){
//        try {
//            exportDir =  Files.createTempDirectory("ca_export").toString();
//        }
//        catch (IOException e) {
//            e.printStackTrace();
//        }}
//
//        String exportPathCACertificate =  Paths.get(exportDir, "root-cert.cer").toString();
//        String exportPathSubCACertificate =  Paths.get(exportDir, "subca-cert.cer").toString();
//        String exportPathClientCertificate =  Paths.get(exportDir, "client-cert.cer").toString();
//        String exportPathCAKey =  Paths.get(exportDir, "root-cert.pfx").toString();
//        String exportPathSubCAKey =  Paths.get(exportDir, "subca-cert.pfx").toString();
//        String exportPathClientKey =  Paths.get(exportDir, "client-cert.pfx").toString();
//
//        logger.debug("============================================================================");
//        logger.debug("Erzeugung einer CA, Sub-CA und eines Client-Zertifikats");
//        logger.debug("============================================================================");
//
//        logger.debug("Erzeugung und Export der CA");
//        TestCAFactory cAFactory = new TestCAFactory();
//        try {
//            cAFactory.build();
//        }
//        catch (TestCAFactory.CACreationException | OperatorCreationException e) {
//            e.printStackTrace();
//            fail();
//        }
//        try {
//            cAFactory.exportCAToFile(exportPathCACertificate,exportPathCAKey);
//        }
//        catch (TestCAFactory.CANotYetCreatedException | TestCAFactory.CAExportException e) {
//            e.printStackTrace();
//            fail();
//        }
//        logger.debug("Die CA wurde erstellt und in {} und {} exportiert", exportPathCACertificate,exportPathCAKey);
//        logger.debug("============================================================================");
//
//        logger.debug("Erzeugung und Export der Sub-CA");
//        TestSubCAFactory subCAFactory = new TestSubCAFactory(cAFactory.getRootCert(), cAFactory.getRootKeyPair());
//        try {
//            subCAFactory.build();
//        }
//        catch (TestSubCAFactory.SubCACreationException | OperatorCreationException e) {
//            e.printStackTrace();
//            fail();
//        }
//
//        try {
//            subCAFactory.exportSubCAToFile(exportPathSubCACertificate, exportPathSubCAKey);
//        }
//
//        catch (TestSubCAFactory.SubCANotYetCreatedException| TestSubCAFactory.SubCAExportException  e) {
//            e.printStackTrace();
//            fail();
//        }
//
//        logger.debug("Die Sub-CA wurde erstellt und in {} und {} exportiert", exportPathSubCACertificate, exportPathSubCAKey);
//        logger.debug("============================================================================");
//
//
//
//        logger.debug("Erzeugung und Export eines Client-Zertifikats");
//        logger.debug("============================================================================");
//        TestClientCertificateFactory clientCertFactory = new TestClientCertificateFactory(subCAFactory.getSubCACert(), subCAFactory.getSubCAKeyPair());
//
//
//        try {
//            clientCertFactory.build();
//        }
//        catch (OperatorCreationException | TestClientCertificateFactory.ClientCertificateCreationException e) {
//            e.printStackTrace();
//            fail();
//        }
//
//        try {
//            clientCertFactory.exportClientCertToFile(exportPathClientCertificate,exportPathClientKey);
//        }
//        catch (TestClientCertificateFactory.ClientCertificateNotYetCreatedException | TestClientCertificateFactory.clientCertExportException e) {
//            e.printStackTrace();
//            fail();
//        }
//
//        logger.debug("Ein Client Zertifikat wurde erstellt und in {} und {} exportiert", exportPathClientCertificate, exportPathClientKey);
//        logger.debug("============================================================================");
//
//
//        logger.debug("Erstellen einer Audit Log Message", exportPathClientCertificate, exportPathClientKey);
//        logger.debug("============================================================================");
//
//        TestAuditLogMessageFactory auditLogMessageFactory = new TestAuditLogMessageFactory();
//
//        auditLogMessageFactory.prepare();
//        try {
//            auditLogMessageFactory.calculateDTBS();
//        } catch (TestLogMessageFactory.TestLogMessageCreationError testLogMessageCreationError) {
//            testLogMessageCreationError.printStackTrace();
//        }
//        try {
//            auditLogMessageFactory.sign(clientCertFactory.clientKeyPair.getPrivate());
//        } catch (TestLogMessageFactory.TestLogMessageCreationError testLogMessageCreationError) {
//            testLogMessageCreationError.printStackTrace();
//        }
//
//        auditLogMessageFactory.build();
//
//        byte[] auditMessage = auditLogMessageFactory.finalizeMessage();
//        String filename = auditLogMessageFactory.getFilename();
//        try {
//            String test = auditLogMessageFactory.exportLogMessageToFolder(Paths.get(exportDir).toString());
//        } catch (TestLogMessageFactory.TestLogMessageExportError testLogMessageExportError) {
//            testLogMessageExportError.printStackTrace();
//            fail();
//        }
//
//        logger.debug("Die AuditLogMessage wurde erstellt und wird jetzt zum testen verwendet");
//
//        try {
//            AuditLogMessage auditLogMessage = new AuditLogMessage(auditMessage, filename);
//        } catch (BadFormatForLogMessageException e) {
//            e.printStackTrace();
//            fail();
//        }
//
//
//    }
}
