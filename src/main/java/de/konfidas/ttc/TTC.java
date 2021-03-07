package de.konfidas.ttc;

import de.konfidas.ttc.exceptions.CerticateLoadException;
import de.konfidas.ttc.tars.TarFile;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.Options;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.security.cert.X509Certificate;

public class TTC {

    private static Options options = new Options();
    final static Logger logger = LoggerFactory.getLogger(TTC.class);

    public static void main(String[] args) throws IOException {
        Security.addProvider(new BouncyCastleProvider());

        options.addOption("i", "inputTAR", true, "Das TAR Archiv, das geprüft werden soll.");
        options.addOption("t", "trustAnker", true, "Trust Anker in Form eines X.509 Zertifikats für die Root-CA");
        options.addOption("o", "overwriteCertCheck", false, "Wenn diese Option gesetzt wird, werden die Zertifikate im TAR Archiv nicht gegen eine Root-CA geprüft");

        CommandLineParser parser = new GnuParser();
        CommandLine cmd = null;

        String trustCertPath = "";
        X509Certificate trustedCert = null;

        /*********************************
         ** Argumente des Aufrufs prüfen *
         *********************************/
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
                try {
                    byte[] certFileContent = Files.readAllBytes(Path.of(trustCertPath));
                    trustedCert = TarFile.loadCertificate(certFileContent);
                }
                catch (CerticateLoadException | IOException e) {
                    e.printStackTrace();
                }
            }

            TarFile tar = new TarFile(new File(cmd.getOptionValue("i")));
            tar.verify(trustedCert, cmd.hasOption("o"));

        }
        catch (Exception e) {
            logger.error("Fehler beim parsen der Kommandozeile. " + e.getLocalizedMessage());
        }
    }
}
