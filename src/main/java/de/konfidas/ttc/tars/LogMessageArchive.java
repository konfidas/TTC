package de.konfidas.ttc.tars;

import de.konfidas.ttc.exceptions.*;
import de.konfidas.ttc.exceptions.BadFormatForTARException;
import de.konfidas.ttc.messages.*;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.operator.AlgorithmNameFinder;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class LogMessageArchive {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);

    ArrayList<LogMessage> all_log_messages = new ArrayList<LogMessage>();
    HashMap<String, X509Certificate> allClientCertificates = new HashMap<String, X509Certificate>();
    HashMap<String, X509Certificate> allIntermediateCertificates = new HashMap<String, X509Certificate>();
    Boolean infoCSVPresent = false;

    public LogMessageArchive() throws IOException, BadFormatForTARException {
        this(null);
    }

    public LogMessageArchive(File tarFile) throws IOException, BadFormatForTARException {
        if( null != tarFile){
            this.parse(tarFile);
        }
    }

    public void parse(File tarFile) throws IOException, BadFormatForTARException{
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
                    infoCSVPresent = true;
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
                        // Prüfe die Eigenschaften des Zertifikats gegen den Dateinamen
                        boolean[] keyUsage = cer.getKeyUsage();
                        if (keyUsage == null || !keyUsage[5]) {
                            allClientCertificates.put(individualFileName.split("_")[0].toUpperCase(), cer);
                            this.validateCertificateAgainstFilename(cer, individualFileName);
                        } else {
                            allIntermediateCertificates.put(individualFileName.split("_")[0].toUpperCase(), cer);
                        }
                    } catch (CertificateLoadException e) {
                        logger.error("Fehler beim Laden des Zertifikats {}", individualFileName);
                    }
                    catch (CertificateInconsistentToFilenameException e) {
                        logger.error("Im Zertifikat {} ist die Konsistenzprüfung fehlgeschlagen. Es wird ignoriert.", individualFileName);
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

        if (!infoCSVPresent){throw new BadFormatForTARException("Die info.csv Datei wurde nicht gefunden",null);}
    }

    public ArrayList<LogMessage> getAll_log_messages(){
        return this.all_log_messages;
    }


    // found at https://stackoverflow.com/questions/28172710/java-compact-representation-of-ecc-publickey
    public static byte[] toUncompressedPoint(final ECPublicKey publicKey) {

        int keySizeBytes = (publicKey.getParams().getOrder().bitLength() + Byte.SIZE - 1)
                / Byte.SIZE;

        final byte[] uncompressedPoint = new byte[1 + 2 * keySizeBytes];
        int offset = 0;
        uncompressedPoint[offset++] = 0x04;

        final byte[] x = publicKey.getW().getAffineX().toByteArray();
        if (x.length <= keySizeBytes) {
            System.arraycopy(x, 0, uncompressedPoint, offset + keySizeBytes
                    - x.length, x.length);
        } else if (x.length == keySizeBytes + 1 && x[0] == 0) {
            System.arraycopy(x, 1, uncompressedPoint, offset, keySizeBytes);
        } else {
            throw new IllegalStateException("x value is too large");
        }
        offset += keySizeBytes;

        final byte[] y = publicKey.getW().getAffineY().toByteArray();
        if (y.length <= keySizeBytes) {
            System.arraycopy(y, 0, uncompressedPoint, offset + keySizeBytes
                    - y.length, y.length);
        } else if (y.length == keySizeBytes + 1 && y[0] == 0) {
            System.arraycopy(y, 1, uncompressedPoint, offset, keySizeBytes);
        } else {
            throw new IllegalStateException("y value is too large");
        }

        return uncompressedPoint;
    }


    public static void validateCertificateAgainstFilename(X509Certificate cert, String filename) throws CertificateInconsistentToFilenameException {
        X500Name certSubject = null;
        try {
            certSubject = new JcaX509CertificateHolder(cert).getSubject();
        } catch (CertificateEncodingException e) {
            throw new CertificateInconsistentToFilenameException(String.format("Fehler bei der Konsistenzprüfung des Zertifikats %s", filename),e);
        }

        RDN cn = certSubject.getRDNs(BCStyle.CN)[0];

        String certSubjectClean = IETFUtils.valueToString(cn.getFirst().getValue()).toUpperCase();

        String keyHashFromFilename = filename.split("_")[0].toUpperCase();

        if (!(certSubjectClean.equals(keyHashFromFilename))){
            throw new CertificateInconsistentToFilenameException(String.format("Der Dateiname %s passt nicht zum Subject des Zertifikats", filename),null);
        }

        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new CertificateInconsistentToFilenameException(String.format("Fehler bei der Konsistenzprüfung des Zertifikats %s", filename),e);
        }

        byte[] encodedCertPublicKey = toUncompressedPoint((ECPublicKey) cert.getPublicKey());

        byte[] hash = digest.digest(encodedCertPublicKey);
        String sha256HexString = Hex.encodeHexString(hash).toUpperCase();

        if (!(sha256HexString.equals(keyHashFromFilename))){
            throw new CertificateInconsistentToFilenameException(String.format("Der Dateiname %s passt nicht zum Hash des PublicKeys (%s)", filename, sha256HexString),null);
        }

    }


    /**
     * Diese Funktion prüft (per Minimum) die Gültigkeit der Signaturen aller LogMessages im TAR-Archiv. Optional kann auch die Gültigkeit der dabei verwendeten Zertifikate geprüft und auf einen Trust-Ancor zurückgeführt werden.
     * @param trustedCert Das Zertifikat, das als TrustAncor verwendet werden soll
     * @param ignoreCertificate Wenn dieser Parameter auf true gesetzt wird, werden die Zertifikate der TSE nicht auf den TrustAncor zurückgeführt
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
