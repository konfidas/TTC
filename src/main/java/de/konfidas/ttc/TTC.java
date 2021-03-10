package de.konfidas.ttc;

import de.konfidas.ttc.exceptions.CertificateLoadException;
import de.konfidas.ttc.messages.LogMessage;
import de.konfidas.ttc.messages.LogMessagePrinter;
import de.konfidas.ttc.tars.LogMessageArchive;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.Options;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.security.cert.X509Certificate;

import static ch.qos.logback.classic.Level.*;

public class TTC {

    private static Options options = new Options();
    final static ch.qos.logback.classic.Logger logger =  (ch.qos.logback.classic.Logger)LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);

    public static void main(String[] args) throws IOException {
        Security.addProvider(new BouncyCastleProvider());

        options.addOption("i", "inputTAR", true, "Das TAR Archiv, das geprüft werden soll.");
        options.addOption("t", "trustAnker", true, "Trust Anker in Form eines X.509 Zertifikats für die Root-CA");
        options.addOption("o", "overwriteCertCheck", false, "Wenn diese Option gesetzt wird, werden die Zertifikate im TAR Archiv nicht gegen eine Root-CA geprüft");
        options.addOption("v", "overwriteCertCheck", false, "Wenn diese Option gesetzt wird, gibt TTC detaillierte Informationen aus.");

        CommandLineParser parser = new GnuParser();
        CommandLine cmd = null;

        String trustCertPath = "";
        X509Certificate trustedCert = null;

        /*********************************
         ** Argumente des Aufrufs prüfen *
         *********************************/
        try {
            cmd = parser.parse(options, args);
            if (cmd.hasOption("v")){
                logger.setLevel(DEBUG);
            }
            if (cmd.hasOption("i") == false) {
                System.err.println("Fehler beim Parsen der Kommandozeile. Kein TAR-Archiv zur Prüfung angegeben");
            }
            if (cmd.hasOption("t") == false && cmd.hasOption("o") == false) {
                System.err.println("Fehler beim Parsen der Kommandozeile. Es muss entweder ein TrustStore für Root-Zertifikate angegeben werden (Option t) oder auf die Prüfung von Zertifikaten verzichtet werden (Option -o)");
            }

            if (cmd.hasOption("t")) {
                trustCertPath = cmd.getOptionValue("t");
                try {
                    byte[] certFileContent = Files.readAllBytes(Path.of(trustCertPath));
                    trustedCert = LogMessageArchive.loadCertificate(certFileContent);
                }
                catch (CertificateLoadException | IOException e) {
                    e.printStackTrace();
                }
            }

            LogMessageArchive tar = new LogMessageArchive(new File(cmd.getOptionValue("i")));
            for (LogMessage message : tar.getAll_log_messages()) {
                logger.debug(LogMessagePrinter.printMessage(message));
            }

            tar.verify(trustedCert, cmd.hasOption("o"));

        }
        catch (Exception e) {
            logger.error("Fehler beim parsen der Kommandozeile. " + e.getLocalizedMessage());
        }
    }
}
