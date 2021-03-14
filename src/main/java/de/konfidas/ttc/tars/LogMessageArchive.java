package de.konfidas.ttc.tars;

import de.konfidas.ttc.exceptions.*;
import de.konfidas.ttc.messages.LogMessage;
import de.konfidas.ttc.messages.LogMessageFactory;
import de.konfidas.ttc.messages.LogMessageSignatureVerifier;
import de.konfidas.ttc.utilities.CertificateHelper;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.operator.AlgorithmNameFinder;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
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
                        X509Certificate cer = CertificateHelper.loadCertificate(content);
                        // Prüfe die Eigenschaften des Zertifikats gegen den Dateinamen
                        boolean[] keyUsage = cer.getKeyUsage();
                        if (keyUsage == null || !keyUsage[5]) {
                            allClientCertificates.put(individualFileName.split("_")[0].toUpperCase(), cer);
                            CertificateValidator.validateCertificateAgainstFilename(cer, individualFileName);
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
                    Boolean result = CertificateValidator.checkCert(cert, trustedCert, new ArrayList<X509Certificate>(allIntermediateCertificates.values()));
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

}
