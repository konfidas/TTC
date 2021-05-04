package de.konfidas.ttc.tars;

import de.konfidas.ttc.exceptions.*;
import de.konfidas.ttc.messages.LogMessageFactory;
import de.konfidas.ttc.messages.LogMessage;
import de.konfidas.ttc.messages.LogMessageImplementation;
import de.konfidas.ttc.utilities.CertificateHelper;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;


public class LogMessageArchiveImplementation implements LogMessageArchive {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);

    final ArrayList<LogMessage> all_log_messages = new ArrayList<>();
    final HashMap<String, X509Certificate> allClientCertificates = new HashMap<>();
    final HashMap<String, X509Certificate> allIntermediateCertificates = new HashMap<>();
    Boolean infoCSVPresent = false;

    public LogMessageArchiveImplementation() throws IOException, BadFormatForTARException {
        this(null);
    }

    public LogMessageArchiveImplementation(File tarFile) throws IOException, BadFormatForTARException {
        if( null != tarFile){
            this.parse(tarFile);
        }
    }

    public HashMap<String, X509Certificate> getIntermediateCertificates(){return allIntermediateCertificates;}
    public HashMap<String, X509Certificate> getClientCertificates(){return allClientCertificates;}

    public void parse(File tarFile) throws IOException, BadFormatForTARException{
        /********************************************************************
         ** Wir lesen nun einmal durch das TAR Archiv (ohne es zu entpacken)*
         ********************************************************************/
        try(TarArchiveInputStream myTarFile = new TarArchiveInputStream(new FileInputStream(tarFile))) {
            TarArchiveEntry entry;
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
                    logger.debug("info.csv gefunden. Starte Verarbeitung.");
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

        if (!infoCSVPresent){throw new BadFormatForTARException("Die info.csv Datei wurde nicht gefunden",null);}
    }

    public ArrayList<LogMessage> getLogMessages(){
        return this.all_log_messages;
    }

    ArrayList<LogMessage> sortedLogMessages;

    public ArrayList<LogMessage> getSortedLogMessages(){
        if(null == sortedLogMessages){
            sortedLogMessages = new ArrayList<>(getLogMessages());
            sortedLogMessages.sort(new LogMessageImplementation.SignatureCounterComparator());
        }

        return sortedLogMessages;
    }

}
