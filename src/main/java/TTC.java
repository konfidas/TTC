import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import java.security.Security;

import org.apache.commons.cli.*;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.bouncycastle.asn1.*;
import org.bouncycastle.jcajce.provider.asymmetric.X509;
import org.bouncycastle.operator.AlgorithmNameFinder;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class TTC {

    private static Options options = new Options();
    final static Logger logger = LoggerFactory.getLogger(TTC.class);
    static ArrayList<LogMessage> all_log_messages = new ArrayList<LogMessage>();
    static HashMap<String, X509Certificate> allClientCertificates = new HashMap<String, X509Certificate>();
    static HashMap<String, X509Certificate> allIntermediateCertificates = new HashMap<String, X509Certificate>();


    public static void main(String[] args) throws IOException {
        Security.addProvider(new BouncyCastleProvider());

        options.addOption("h", "Hilfe", false, "zeige die Hilfe.");
        options.addOption("i", "InputTAR", true, "Das TAR Archiv, das geprüft werden soll.");
        options.addOption("t", "TrustAnker", true, "Trust Anker in Form eines X.509 Zertifikats für die Root-CA");
        options.addOption("o", "OverwriteCertCheck", false, "Wenn diese Option gesetzt wird, werden die Zertifikate im TAR Archiv nicht gegen eine Root-CA geprüft");

        CommandLineParser parser = new GnuParser();
        CommandLine cmd = null;

        String trustCertPath = "";
        X509Certificate trustedCert = null;

        try {
            cmd = parser.parse(options, args);
            if (cmd.hasOption("i") == false) {
                System.err.println("Fehler beim Parsen der Kommandozeile. Kein TAR-Archiv zur Prüfung angegeben");
            }
            if (cmd.hasOption("t") == false && cmd.hasOption("o") == false) {
                System.err.println("Fehler beim Parsen der Kommandozeile. Es muss entweder ein TrustStore für Root-Zertifikate angegeben werden (Option t) oder auf die Prüfung von Zertifikaten verzichtet werden (Option -o)");
            }

            if (cmd.hasOption("t")) {
                trustCertPath = cmd.getOptionValue("t");
            }

        } catch (Exception e) {
            logger.error("Fehler beim parsen der Kommandozeile. " + e.getLocalizedMessage());
        }

//        Sofern wir das Zertifikat für die RootCA brauchen, laden wir es jetzt
        if (cmd.hasOption("o") == false) {

                // FIXME: Call verification function

            }

        /* Wir lesen nun einmal durch das TAR Archiv (ohne es zu entpacken)*/
        try {
            TarArchiveInputStream myTarFile = new TarArchiveInputStream(new FileInputStream(new File(cmd.getOptionValue("i"))));

            /* To read individual TAR file */
            TarArchiveEntry entry = null;
            String individualFileName;

            int offset;
            FileOutputStream outputFile = null;
            /* Create a loop to read every single entry in TAR file */
            while ((entry = myTarFile.getNextTarEntry()) != null) {
                /* Get the name of the file */
                individualFileName = entry.getName();

                /* Get Size of the file and create a byte array for the size */
                byte[] content = new byte[(int) entry.getSize()];
                offset = 0;

                myTarFile.read(content, offset, content.length - offset);

                if (individualFileName.matches("^(Gent_|Unixt_|Utc_).+_Sig-\\d+_Log-.+(Start|Update|Finish)_Client-.+log")) {
                    logger.info("{} seems to be a transaction log. Will process it now.", individualFileName);
                    TransactionLogMessage log = new TransactionLogMessage(content, individualFileName);
                    all_log_messages.add(log);

                } else if (individualFileName.matches("^(Gent_|Unixt_|Utc_)\\d+_Sig-\\d+_Log-Sys.+log")) {
                    logger.info("{} seems to be a system log. Will process it now.", individualFileName);
                    SystemLogMessage log = new SystemLogMessage(content, individualFileName);
                    all_log_messages.add(log);

                } else if (individualFileName.matches("^(Gent_|Unixt_|Utc_)\\d+_Sig-\\d+_Log-Aud.+log")) {
                    logger.info("{} seems to be a audit log. Will process it now.", individualFileName);
                    AuditLogMessage log = new AuditLogMessage(content, individualFileName);
                    all_log_messages.add(log);

                } else if (individualFileName.contains("CVC")) {
                    logger.info("{} seems to be a CVC. Will process it now.", individualFileName);

                } else if (individualFileName.contains("X509")) {
                    logger.info("{} seems to be an X509 certificate. Will process it now.", individualFileName);

                    try {
                        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
                        InputStream in = new ByteArrayInputStream(content);
                        X509Certificate cer = (X509Certificate) cf.generateCertificate(in);

                        //Prüfen, dass das Zertifikat gültig ist
                        cer.checkValidity();

                        //Als nächstes prüfen wir, ob das Zertifikat die keyUsage für crlSign hat. In dem Fall behandeln wir es als intermedite Zertifikat, ansonsten als Client-Zert
                        boolean[] keyUsage = cer.getKeyUsage();
                        if (keyUsage == null || keyUsage[5] == false) {
                            allClientCertificates.put(individualFileName.split("_")[0].toUpperCase(), cer);
                        } else {
                            allIntermediateCertificates.put(individualFileName.split("_")[0].toUpperCase(), cer);
                        }

                    } catch (CertificateExpiredException e) {
                        logger.error("{} contains an expired certificate", individualFileName);
                    } catch (CertificateNotYetValidException e) {
                        logger.error("{} contains a certificate that is not yet valid", individualFileName);
                    } catch (java.security.cert.CertificateException e) {
                        throw new RuntimeException(e);
                    } catch (NoSuchProviderException e) {
                        e.printStackTrace();
                    }
                } else {
                    logger.error("{} sollte nicht in der TAR Datei vorhanden sein. Es wird ignoriert.", individualFileName);
                }
            }

            // Nun geben wir alle Nachrichten einmal aus.
            for (int i = 0; i < all_log_messages.size(); i++) {
                System.out.println(all_log_messages.get(i).prettyPrint());
            }


            //Sofern nicht darauf verzichtet wid, prüfen wir die Gültikeit der Client-Zertifikate
            if (cmd.hasOption("o") == false) {
                for (X509Certificate cert : allClientCertificates.values()) {
                    try {
                        Boolean result = checkCert(cert, trustStore, new ArrayList<X509Certificate>(allIntermediateCertificates.values()));
                        logger.info("Prüfe das Zertifikat mit Seriennummer {} auf Korrektheit und prüfe die zugehörige Zertifikatskette. Ergebnis ist {}", cert.getSerialNumber(), result.toString());
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }

            // Im nächsten Schritt prüfen wir alle Signaturen der Log-Messages einmal
            for (int i = 0; i < all_log_messages.size(); i++) {
                try {
                    assertSignatureOfLogMessageIsValid(all_log_messages.get(i), allClientCertificates.get(all_log_messages.get(i).serialNumber));
                    logger.info("Prüfe die Signatur der LogMessage {}", all_log_messages.get(i).filename);
                } catch (SignatureValidationException signatureValidationException) {
                    logger.error("Fehler bei der Prüfung der Signatur");
                }
            }
            myTarFile.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            System.exit(1);
        }
    }


    public static X509Certificate loadCertificate(byte[] certContent){


    }
    /**
     * @param certToCheck       Das Zertifikat, dessen Gültigkeit geprüft ewrden soll
     * @param trustStore        Ein TrustStore, der das Root-Zertifikat enthält
     * @param intermediateCerts Die Liste der Intermediate-Zertifikate, die für eine Chain zwischen certToCheck und dem Zertifikat im TrustStore benötigt werden.
     * @return
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchProviderException
     * @throws CertPathValidatorException
     * @throws CertificateException
     */
    public static boolean checkCert(X509Certificate certToCheck, X509Certificate trustedCert, List<X509Certificate> intermediateCerts) throws NoSuchAlgorithmException, KeyStoreException, InvalidAlgorithmParameterException, NoSuchProviderException, CertPathValidatorException, CertificateException {
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
    public static void assertSignatureOfLogMessageIsValid(LogMessage logMessageToVerify, X509Certificate certForVerification) throws SignatureValidationException {

        if (certForVerification == null) {
            throw new SignatureValidationException("Es wurde kein gültiges Zertifikat für die Prüfung der Signatur übergeben", new NullPointerException());
        }
        if (logMessageToVerify == null) {
            throw new SignatureValidationException("Es wurde keine LogMessage für die Prüfung der Signatur übergeben", new NullPointerException());
        }
        try {
            ASN1ObjectIdentifier algoIdentifier = new ASN1ObjectIdentifier(logMessageToVerify.signatureAlgorithm);
            AlgorithmNameFinder nameFinder = new DefaultAlgorithmNameFinder();
            String algoName = nameFinder.getAlgorithmName(algoIdentifier);

            Signature st = Signature.getInstance(algoName, "BC");
            st.initVerify(certForVerification.getPublicKey());

            st.update(logMessageToVerify.dtbs);

            byte[] signatureValue = logMessageToVerify.signatureValue;
            String testString = Hex.encodeHexString(signatureValue);
            Boolean resultSignatureVerification = st.verify(signatureValue);

        } catch (NoSuchProviderException e) {
            throw new SignatureValidationException("Bouncy Castle wurde als Provider nicht gefunden", e);
        } catch (NoSuchAlgorithmException e) {
            throw new SignatureValidationException("Der Algorithmus wird nicht unterstützt", e);
        } catch (SignatureException e) {
            throw new SignatureValidationException("Die Signatur konnte nicht verifiziert werden.", e);
        } catch (InvalidKeyException e) {
            logger.error("Der Schlüssel zur Prüfung der Signatur konnte nicht eingelesen werden.", e);
        }

    }


}
