package de.konfidas.ttc.tars;

import de.konfidas.ttc.exceptions.CerticateLoadException;
import de.konfidas.ttc.exceptions.SignatureValidationException;
import de.konfidas.ttc.messages.AuditLogMessage;
import de.konfidas.ttc.messages.LogMessage;
import de.konfidas.ttc.messages.SystemLogMessage;
import de.konfidas.ttc.messages.TransactionLogMessage;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.operator.AlgorithmNameFinder;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class TarFile {
    final static Logger logger = LoggerFactory.getLogger(TarFile.class);

    ArrayList<LogMessage> all_log_messages = new ArrayList<LogMessage>();
    HashMap<String, X509Certificate> allClientCertificates = new HashMap<String, X509Certificate>();
    HashMap<String, X509Certificate> allIntermediateCertificates = new HashMap<String, X509Certificate>();


    public  TarFile() throws IOException {
        this(null);
    }

    public TarFile(File tarFile) throws IOException {
        if( null != tarFile){
            this.parse(tarFile);
        }
    }

    public void parse(File tarFile) throws IOException {
        /********************************************************************
         ** Wir lesen nun einmal durch das TAR Archiv (ohne es zu entpacken)*
         ********************************************************************/
        try {
            TarArchiveInputStream myTarFile = new TarArchiveInputStream(new FileInputStream(tarFile));
            TarArchiveEntry entry = null;
            String individualFileName;
            int offset;

            while ((entry = myTarFile.getNextTarEntry()) != null) {
                /* Get the name of the file */
                individualFileName = entry.getName();

                /* Get Size of the file and create a byte array for the size */
                byte[] content = new byte[(int) entry.getSize()];
                offset = 0;

                myTarFile.read(content, offset, content.length - offset);

                /***************************
                 ** TransactionLog Message *
                 ***************************/
                if (individualFileName.matches("^(Gent_|Unixt_|Utc_).+_Sig-\\d+_Log-.+(Start|Update|Finish)_Client-.+log")) {
                    logger.info("{} scheint eine TransactionLog zu sein. Starte Verarbeitung.", individualFileName);
                    TransactionLogMessage log = new TransactionLogMessage(content, individualFileName);
                    all_log_messages.add(log);
                }
                /**********************
                 ** SystemLog Message *
                 **********************/
                else if (individualFileName.matches("^(Gent_|Unixt_|Utc_)\\d+_Sig-\\d+_Log-Sys.+log")) {
                    logger.info("{} scheint ein systemLog zu sein. Starte Verarbeitung ", individualFileName);
                    SystemLogMessage log = new SystemLogMessage(content, individualFileName);
                    all_log_messages.add(log);

                }
                /**********************
                 ** AuditLog Message *
                 *********************/
                else if (individualFileName.matches("^(Gent_|Unixt_|Utc_)\\d+_Sig-\\d+_Log-Aud.+log")) {
                    logger.info("{} scheint ein auditLog zu sein. Starte Verarbeitung.", individualFileName);
                    AuditLogMessage log = new AuditLogMessage(content, individualFileName);
                    all_log_messages.add(log);

                }
                /**************
                 ** info.csv *
                 *************/
                else if (individualFileName.matches("^info.csv")) {
                    logger.info("info.csv gefunden. Starte Verarbeitung.", individualFileName);
                    String info_string = new String(content, StandardCharsets.UTF_8);
                    logger.info("Description laut info.csv: {}", StringUtils.substringsBetween(info_string, "description:\",\"", "\"," )[0]);
                    logger.info("Manufacturer laut info.csv: {}", StringUtils.substringsBetween(info_string, "manufacturer:\",\"", "\"," )[0]);
                    logger.info("Version laut info.csv: {}", StringUtils.substringsBetween(info_string, "version:\",\"", "\"" )[0]);
                }
                /*********************
                 ** CVC Certificate *
                 ********************/
                else if (individualFileName.contains("CVC")) {
                    logger.info("{} seems to be a CVC. Will process it now.", individualFileName);

                }
                /**********************
                 ** X.509 Certificate *
                 **********************/
                else if (individualFileName.contains("X509")) {
                    logger.info("{} schein ein X.509 Zertifikat zu sein. Starte Verarbeitung.", individualFileName);

                    try {
                        X509Certificate cer = loadCertificate(content);
                        boolean[] keyUsage = cer.getKeyUsage();
                        if (keyUsage == null || keyUsage[5] == false) {
                            allClientCertificates.put(individualFileName.split("_")[0].toUpperCase(), cer);
                        }
                        else {
                            allIntermediateCertificates.put(individualFileName.split("_")[0].toUpperCase(), cer);
                        }
                    }
                    catch (CerticateLoadException e) {
                        logger.error("Fehler beim Laden des Zertifikats {}", individualFileName);
                    }

                }
                else {
                    logger.error("{} sollte nicht in der TAR Datei vorhanden sein. Es wird ignoriert.", individualFileName);
                }
            }

            /***********************************************
             ** Nun geben wir alle Nachrichten einmal aus.*
             **********************************************/
            for (LogMessage message : all_log_messages) {
                System.out.println(message.prettyPrint());
            }

            myTarFile.close();
        }
        catch (FileNotFoundException e) {
            e.printStackTrace();
            System.exit(1);
        }
    }


    public void verify(   X509Certificate trustedCert, boolean ignoreCertificate){
        /***************************************************************************************
         ** Sofern nicht darauf verzichtet wid, prüfen wir die Gültigkeit der Client-Zertifikate*
         ***************************************************************************************/
        if (!ignoreCertificate) {
            for (X509Certificate cert : allClientCertificates.values()) {
                try {

                    Boolean result = checkCert(cert, trustedCert, new ArrayList<X509Certificate>(allIntermediateCertificates.values()));
                    logger.info("Prüfe das Zertifikat mit Seriennummer {} auf Korrektheit und prüfe die zugehörige Zertifikatskette. Ergebnis ist {}", cert.getSerialNumber(), result.toString());
                }
                catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }

        /***************************************************************************
         ** Im nächsten Schritt prüfen wir alle Signaturen der Log-Messages einmal *
         ***************************************************************************/
        for (LogMessage message : all_log_messages) {
            try {
                assertSignatureOfLogMessageIsValid(message, allClientCertificates.get(message.getSerialNumber()));
                logger.info("Prüfe die Signatur der LogMessage {}", message.getFileName());
            }
            catch (SignatureValidationException signatureValidationException) {
                logger.error("Fehler bei der Prüfung der Signatur der Log Message {}", message.getFileName());
            }
        }
    }

    /**
     * Diese Funktion lädt ein X059Certificat aus einem ByteArray und kümmert sich um die Fehlerbehandlung
     *
     * @param certContent Ein Byte-Array, das das Zertifikat enthält
     * @return das X509Certificate Objekt
     * @throws CerticateLoadException
     */
    public static X509Certificate loadCertificate(byte[] certContent) throws CerticateLoadException {
        X509Certificate cer = null;
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
            InputStream in = new ByteArrayInputStream(certContent);
            cer = (X509Certificate) cf.generateCertificate(in);

            /*******************************************
             ** Prüfen, dass das Zertifikat gültig ist *
             *******************************************/
            cer.checkValidity();

        }
        catch (CertificateExpiredException e) {
            logger.error("Das Zertifikat ist abgelaufen.");
        }
        catch (CertificateNotYetValidException e) {
            logger.error("Das Zertifikat ist noch nicht gültig.");
        }
        catch (java.security.cert.CertificateException e) {
            throw new RuntimeException(e);
        }
        catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return cer;
    }


    /**
     * @param certToCheck       Das Zertifikat, dessen Gültigkeit geprüft ewrden soll
     * @param trustedCert        Ein TrustStore, der das Root-Zertifikat enthält
     * @param intermediateCerts Die Liste der Intermediate-Zertifikate, die für eine Chain zwischen certToCheck und dem Zertifikat im TrustStore benötigt werden.
     * @return
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchProviderException
     * @throws CertPathValidatorException
     * @throws CertificateException
     */
    public static boolean checkCert(X509Certificate certToCheck, X509Certificate
            trustedCert, List<X509Certificate> intermediateCerts) throws
            NoSuchAlgorithmException, KeyStoreException, InvalidAlgorithmParameterException, NoSuchProviderException, CertPathValidatorException, CertificateException {
//FIXME: Noch nicht implementiert
        //        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
//        CertPath path = cf.generateCertPath(intermediateCerts);
//        CertPathValidator validator = CertPathValidator.getInstance("PKIX");

//        Collection<? extends CRL> crls;
//        try (InputStream is = Files.newInputStream(Paths.get("crls.p7c"))) {
//            crls = cf.generateCRLs(is);
//        }
//        PKIXParameters params = new PKIXParameters(trustStore);
//        CertStore store = CertStore.getInstance("Collection",new CollectionCertStoreParameters(), "BC");
////        CertStore store = CertStore.getInstance("Collection", new CollectionCertStoreParameters(crls));
//        /* If necessary, specify the certificate policy or other requirements
//         * with the appropriate params.setXXX() method. */
//        params.addCertStore(store);
//        /* Validate will throw an exception on invalid chains. */
//        PKIXCertPathValidatorResult r = (PKIXCertPathValidatorResult) validator.validate(path, params);
        return true;
    }

    /**
     * @param logMessageToVerify  Das Objekt der LogMessage, deren Signatur verifiziert werden soll
     * @param certForVerification Das Zertifikat, das zur Prüfung der LogMessage verwendet werden soll
     * @throws SignatureValidationException Dieser Fehler wird geworfen fall die Validierung der Signatur fehlschlägt. Im Innern der Exception findet sich die ursprüngliche Exception und eine Fehlernachricht
     */
    public static void assertSignatureOfLogMessageIsValid(LogMessage logMessageToVerify, X509Certificate
            certForVerification) throws SignatureValidationException {

        if (certForVerification == null) {
            throw new SignatureValidationException("Es wurde kein gültiges Zertifikat für die Prüfung der Signatur übergeben", new NullPointerException());
        }
        if (logMessageToVerify == null) {
            throw new SignatureValidationException("Es wurde keine LogMessage für die Prüfung der Signatur übergeben", new NullPointerException());
        }
        try {
            ASN1ObjectIdentifier algoIdentifier = new ASN1ObjectIdentifier(logMessageToVerify.getSignatureAlgorithm());
            AlgorithmNameFinder nameFinder = new DefaultAlgorithmNameFinder();
            String algoName = nameFinder.getAlgorithmName(algoIdentifier);

            Signature st = Signature.getInstance(algoName, "BC");
            st.initVerify(certForVerification.getPublicKey());

            st.update(logMessageToVerify.getDTBS());

            byte[] signatureValue = logMessageToVerify.getSignatureValue();
            st.verify(signatureValue);

        }
        catch (NoSuchProviderException e) {
            throw new SignatureValidationException("Bouncy Castle wurde als Provider nicht gefunden", e);
        }
        catch (NoSuchAlgorithmException e) {
            throw new SignatureValidationException("Der Algorithmus wird nicht unterstützt", e);
        }
        catch (SignatureException e) {
            throw new SignatureValidationException("Die Signatur konnte nicht verifiziert werden.", e);
        }
        catch (InvalidKeyException e) {
            logger.error("Der Schlüssel zur Prüfung der Signatur konnte nicht eingelesen werden.", e);
        }

    }



}
