package de.konfidas.ttc;

import de.konfidas.ttc.exceptions.CertificateLoadException;
import de.konfidas.ttc.exceptions.ValidationException;
import de.konfidas.ttc.messages.LogMessage;
import de.konfidas.ttc.messages.LogMessagePrinter;
import de.konfidas.ttc.tars.LogMessageArchive;
import de.konfidas.ttc.utilities.CertificateHelper;
import de.konfidas.ttc.validation.*;
import org.apache.commons.cli.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;

import static ch.qos.logback.classic.Level.*;

public class TTC {

    final static ch.qos.logback.classic.Logger logger =  (ch.qos.logback.classic.Logger)LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);

    public static void main(String[] args){
        Security.addProvider(new BouncyCastleProvider());

        Options options = new Options();

        options.addOption("i", "inputTAR", true, "Das TAR Archiv, das geprüft werden soll.");
        options.addOption("t", "trustAnker", true, "Trust Anker in Form eines X.509 Zertifikats für die Root-CA");
        options.addOption("o", "overwriteCertCheck", false, "Wenn diese Option gesetzt wird, werden die Zertifikate im TAR Archiv nicht gegen eine Root-CA geprüft");
        options.addOption("v", "overwriteCertCheck", false, "Wenn diese Option gesetzt wird, gibt TTC detaillierte Informationen aus.");

        CommandLineParser parser = new DefaultParser();
//        CommandLineParser parser = new GnuParser();
        CommandLine cmd;

        String trustCertPath;
        X509Certificate trustedCert = null;

        /*********************************
         ** Argumente des Aufrufs prüfen *
         *********************************/
        try {
            cmd = parser.parse(options, args);
            if (cmd.hasOption("v")){
                logger.setLevel(DEBUG);
            }
            if (!cmd.hasOption("i")) {
                System.err.println("Fehler beim Parsen der Kommandozeile. Kein TAR-Archiv zur Prüfung angegeben");
            }
            if (!(cmd.hasOption("t")  ||cmd.hasOption("o"))) {
                System.err.println("Fehler beim Parsen der Kommandozeile. Es muss entweder ein TrustStore für Root-Zertifikate angegeben werden (Option t) oder auf die Prüfung von Zertifikaten verzichtet werden (Option -o)");
            }

            if (cmd.hasOption("t")) {
                trustCertPath = cmd.getOptionValue("t");
                try {
                    trustedCert = CertificateHelper.loadCertificate(Path.of(trustCertPath));
                }catch (CertificateLoadException | IOException e) {
                    e.printStackTrace();
                }
            }

            LogMessageArchive tar = new LogMessageArchive(new File(cmd.getOptionValue("i")));
            for (LogMessage message : tar.getAll_log_messages()) {
                logger.debug(LogMessagePrinter.printMessage(message));
            }

            AggregatedValidator validator = new AggregatedValidator()
                    .add(new CertificateFileNameValidator())
                    .add(new TimeStampValidator())
                    .add(new SignatureCounterValidator())
                    .add(new LogMessageSignatureValidator());

            if(cmd.hasOption("o")) {
                validator.add(new CertificateValidator(Collections.singleton(trustedCert)));
            }

            Collection<ValidationException> errors = validator.validate(tar);
            if(!errors.isEmpty()){
                logger.debug("there were Errors while Validating:");

                for(ValidationException e : errors){
                    if(e instanceof CertificateValidator.CertificateValidationException){
                        CertificateValidator.CertificateValidationException c = (CertificateValidator.CertificateValidationException) e;
                        logger.debug("failed to verify "+c.getCert()+" with error:");
                        logger.debug(c.getError().toString());
                    }else{
                        logger.debug("Error during validation "+ e.toString());
                    }
                }
            }

        }
        catch (Exception e) {
            logger.error("Fehler beim parsen der Kommandozeile. " + e.getLocalizedMessage());
        }
    }
}
