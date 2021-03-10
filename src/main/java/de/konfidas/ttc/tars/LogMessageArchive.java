package de.konfidas.ttc.tars;

import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.exceptions.CertificateLoadException;
import de.konfidas.ttc.exceptions.LogMessageVerificationException;
import de.konfidas.ttc.exceptions.SignatureValidationException;
import de.konfidas.ttc.messages.*;
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

public class LogMessageArchive {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);

    ArrayList<LogMessage> all_log_messages = new ArrayList<LogMessage>();
    HashMap<String, X509Certificate> allClientCertificates = new HashMap<String, X509Certificate>();
    HashMap<String, X509Certificate> allIntermediateCertificates = new HashMap<String, X509Certificate>();


    public LogMessageArchive() throws IOException {
        this(null);
    }

    public LogMessageArchive(File tarFile) throws IOException {
        if( null != tarFile){
            this.parse(tarFile);
        }
    }

    public void parse(File tarFile) throws IOException {
        /********************************************************************
         ** Wir lesen nun einmal durch das TAR Archiv (ohne es zu entpacken)*
         ********************************************************************/
        try(TarArchiveInputStream myTarFile = new TarArchiveInputStream(new FileInputStream(tarFile))) {
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

                logger.info("Verarbeite nun die Datei {}", individualFileName);

                if (individualFileName.matches("^(Gent_|Unixt_|Utc_).+_Sig-\\d+_Log-.+log") ) {
                    all_log_messages.add(LogMessageFactory.createLogMessage(individualFileName,content));
                }

                /**************
                 ** info.csv *
                 *************/
                else if (individualFileName.matches("^info.csv")) {
                    logger.debug("info.csv gefunden. Starte Verarbeitung.", individualFileName);
                    String info_string = new String(content, StandardCharsets.UTF_8);
                    logger.debug("Description laut info.csv: {}", StringUtils.substringsBetween(info_string, "description:\",\"", "\"," )[0]);
                    logger.debug("Manufacturer laut info.csv: {}", StringUtils.substringsBetween(info_string, "manufacturer:\",\"", "\"," )[0]);
                    logger.debug("Version laut info.csv: {}", StringUtils.substringsBetween(info_string, "version:\",\"", "\"" )[0]);
                }
                /*********************
                 ** CVC Certificate *
                 ********************/
                else if (individualFileName.contains("CVC")) {
                    logger.debug("{} seems to be a CVC. Will process it now.", individualFileName);
                    //FIXME: Not supported

                }
                /**********************
                 ** X.509 Certificate *
                 **********************/
                else if (individualFileName.contains("X509")) {
                    logger.debug("{} schein ein X.509 Zertifikat zu sein. Starte Verarbeitung.", individualFileName);

                    try {
                        X509Certificate cer = loadCertificate(content);
                        boolean[] keyUsage = cer.getKeyUsage();
                        if (keyUsage == null || keyUsage[5] == false) {
                            allClientCertificates.put(individualFileName.split("_")[0].toUpperCase(), cer);
                        } else {
                            allIntermediateCertificates.put(individualFileName.split("_")[0].toUpperCase(), cer);
                        }
                    } catch (CertificateLoadException e) {
                        logger.error("Fehler beim Laden des Zertifikats {}", individualFileName);
                    }
                } else {
                    logger.error("{} sollte nicht in der TAR Datei vorhanden sein. Es wird ignoriert.", individualFileName);
                }
            }


        }
        catch (FileNotFoundException | BadFormatForLogMessageException e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    public ArrayList<LogMessage> getAll_log_messages(){
        return this.all_log_messages;
    }


    /**
     * Diese Funktion prüft (per Minimum) die Gültigkeit der Signaturen aller LogMessages im TAR-Archiv. Optional kann auch die Gültigkeit der dabei verwendeten Zertifikate geprüft und auf einen Trust-Ancor zurückgeführt werden.
     * @param trustedCert
     * @param ignoreCertificate
     */
    public void verify(X509Certificate trustedCert, boolean ignoreCertificate){
        /***************************************************************************************
         ** Sofern nicht darauf verzichtet wid, prüfen wir die Gültigkeit der Client-Zertifikate*
         ***************************************************************************************/
        if (!ignoreCertificate) {
            for (X509Certificate cert : allClientCertificates.values()) {
                try {

                    Boolean result = checkCert(cert, trustedCert, new ArrayList<X509Certificate>(allIntermediateCertificates.values()));
                    logger.debug("Prüfe das Zertifikat mit Seriennummer {} auf Korrektheit und prüfe die zugehörige Zertifikatskette. Ergebnis ist {}", cert.getSerialNumber(), result.toString());
                }
                catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }

        /***************************************************************************
         ** Im nächsten Schritt prüfen wir alle Signaturen der Log-Messages einmal *
         ***************************************************************************/
        LogMessageSignatureVerifier verifier = new LogMessageSignatureVerifier(allClientCertificates);
        for (LogMessage message : all_log_messages) {
            try {
                logger.debug("Prüfe die Signatur der LogMessage {}", message.getFileName());
                verifier.verify(message);
            }
            catch (LogMessageVerificationException e) {
                logger.error("Fehler bei der Prüfung der Signatur der Log Message {}", message.getFileName(), e);
            }
        }
    }

    /**
     * Diese Funktion lädt ein X059Certificat aus einem ByteArray und kümmert sich um die Fehlerbehandlung
     *
     * @param certContent Ein Byte-Array, das das Zertifikat enthält
     * @return das X509Certificate Objekt
     * @throws CertificateLoadException
     */
    public static X509Certificate loadCertificate(byte[] certContent) throws CertificateLoadException {
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
     * @param certToCheck       Das Zertifikat, dessen Gültigkeit geprüft werden soll
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
