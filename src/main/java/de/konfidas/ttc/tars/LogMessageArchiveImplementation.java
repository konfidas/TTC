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
import java.util.*;


public class LogMessageArchiveImplementation implements LogMessageArchive {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);

    static Locale locale = new Locale("de", "DE"); //NON-NLS
    static ResourceBundle properties = ResourceBundle.getBundle("ttc",locale);//NON-NLS
    final ArrayList<LogMessage> all_log_messages = new ArrayList<>();
    final HashMap<String, X509Certificate> allClientCertificates = new HashMap<>();
    final HashMap<String, X509Certificate> allIntermediateCertificates = new HashMap<>();
    final ArrayList<Exception> allErrors = new ArrayList<>(); //This list will hold all the errors that occur during parsing.
    Boolean infoCSVPresent = false;
    String filename;


    public LogMessageArchiveImplementation() {
        this(null);

    }

    public LogMessageArchiveImplementation(File tarFile) {

        if( null != tarFile){
            this.filename= tarFile.getName();
            this.parse(tarFile);
        }
    }

    public HashMap<String, X509Certificate> getIntermediateCertificates(){return allIntermediateCertificates;}
    public HashMap<String, X509Certificate> getClientCertificates(){return allClientCertificates;}

    public void parse(File tarFile){
        /**********************************************************
         ** We will parse the TAR file without unpacking it       *
         **********************************************************/
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

                logger.debug("Will now process {}", individualFileName); //NON-NLS

                if (individualFileName.matches("^(Gent_|Unixt_|Utc_).+_Sig-\\d+_Log-.+log") ) {//NON-NLS
                    try{
                    all_log_messages.add(LogMessageFactory.createLogMessage(individualFileName,content));
                    }
                    catch (BadFormatForLogMessageException e){
                        this.allErrors.add(e);
                    }
                }

                /**************
                 ** info.csv *
                 *************/
                else if (individualFileName.matches("^info.csv")) {//NON-NLS
                    logger.debug("found info.csv. Start processing now.");//NON-NLS
                    infoCSVPresent = true;
                    String info_string = new String(content, StandardCharsets.UTF_8);
                    logger.debug("Description in info.csv: {}", StringUtils.substringsBetween(info_string, "description:\",\"", "\"," )[0]);//NON-NLS
                    logger.debug("Manufacturer in info.csv: {}", StringUtils.substringsBetween(info_string, "manufacturer:\",\"", "\"," )[0]);//NON-NLS
                    logger.debug("Version in info.csv: {}", StringUtils.substringsBetween(info_string, "version:\",\"", "\"" )[0]);//NON-NLS
                }
                /*********************
                 ** CVC Certificate *
                 ********************/
                else if (individualFileName.contains("CVC")) {
                    logger.debug("{} seems to be a CVC certificate. This is currently not supported by TTC.", individualFileName);//NON-NLS
                    allErrors.add(new GeneralTARFileError(String.format(properties.getString("de.konfidas.ttc.tars.cvcNotSuported"),individualFileName)));

                }
                /**********************
                 ** X.509 Certificate *
                 **********************/
                else if (individualFileName.contains("X509")) {//NON-NLS
                    logger.debug("{} seems to be an X.509 certificate. Will process it now.", individualFileName);//NON-NLS
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
                        logger.debug("Error loading certificate {}", individualFileName);//NON-NLS
                        allErrors.add(new GeneralTARFileError(String.format(properties.getString("de.konfidas.ttc.tars.errorLoadingCertificateWhenParsingTAR"),individualFileName),e));
                    }
                } else {
                    logger.debug("{} should not be in the TAR file. Will be ignored.", individualFileName);//NON-NLS
                    allErrors.add(new GeneralTARFileError(String.format(properties.getString("de.konfidas.ttc.tars.fileShouldNotBeInTAR"),individualFileName)));

                }
            }
        }
        catch ( IOException  e) {
            allErrors.add(e);
        }

        if (!infoCSVPresent){
            allErrors.add( new BadFormatForTARException(properties.getString("de.konfidas.ttc.tars.infoCSVNotFound"),null));
        }
    }

    public ArrayList<LogMessage> getLogMessages(){
        return this.all_log_messages;
    }

    @Override
    public String getFileName() {
        return filename;
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
