package de.konfidas.ttc;

import de.konfidas.ttc.exceptions.BadFormatForTARException;
import de.konfidas.ttc.exceptions.CertificateLoadException;
import de.konfidas.ttc.exceptions.ValidationException;
import de.konfidas.ttc.messages.LogMessage;
import de.konfidas.ttc.messages.LogMessagePrinter;
import de.konfidas.ttc.reporting.HtmlReporter;
import de.konfidas.ttc.reporting.Reporter;
import de.konfidas.ttc.reporting.TextReporter;
import de.konfidas.ttc.tars.LogMessageArchive;
import de.konfidas.ttc.tars.LogMessageArchiveImplementation;
import de.konfidas.ttc.utilities.CertificateHelper;
import de.konfidas.ttc.validation.*;
import org.apache.commons.cli.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.*;

import static ch.qos.logback.classic.Level.*;

public class TTC {

    final static ch.qos.logback.classic.Logger logger = (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    static Locale locale = new Locale("de", "DE");
    static ResourceBundle properties = ResourceBundle.getBundle("ttc",locale);

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        Options options = new Options();

        options.addOption("t", "trustAnker", true, properties.getString("de.konfidas.ttt.help_rootCA"));
        options.addOption("h", "help", false, "Drucke Informationen zum Programm");
        options.addOption("n", "noCertCheck", false, "Wenn diese Option gesetzt wird, werden die Zertifikate im TAR Archiv nicht gegen eine Root-CA geprüft");
        options.addOption("d", "debug", false, "Wenn diese Option gesetzt wird, gibt TTC detaillierte Informationen aus.");
        options.addOption("e", "errorsOnly", false, "Wenn diese Option gesetzt wird, gibt TTC ausschließlich Informationen  über fehlerhafte Messages aus. Informationen über korrekte LogMessages werden unterdrückt.");
        options.addOption("g", "generateHtmlReport", true, "Generiere einen HTML Output.");
        options.addOption("v", "validator", true, "Benutze einen oder mehrere ausgewählte Validatoren. Mehrere Validatoren können durch Kommata getrennt angegeben werden. Die folgenden Validatoren stehen zur Verfügung: de.konfidas.ttc.validation.CertificateFileNameValidator, de.konfidas.ttc.validation.TimeStampValidator, de.konfidas.ttc.validation.SignatureCounterValidator, de.konfidas.ttc.validation.LogMessageSignatureValidator.");

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd;

        String trustCertPath;
        X509Certificate trustedCert = null;
        Boolean skipLegitLogMessagesInReporting = false;
        Collection<Validator> listOfValidators = new ArrayList<>();


        /*********************************
         ** Argumente des Aufrufs prüfen *
         *********************************/
        try {
            cmd = parser.parse(options, args);
            if (cmd.hasOption("d")) {
                logger.setLevel(DEBUG);
            }
            if (cmd.hasOption("h")) {
                HelpFormatter formatter = new HelpFormatter();
                formatter.setWidth(120);
                formatter.printHelp("ttc", options );
                System.exit(0);
            }
            if (cmd.hasOption("e")) {
                skipLegitLogMessagesInReporting = true;
            }

            if (!(cmd.hasOption("t") || cmd.hasOption("n"))) {
                System.err.println("Fehler beim Parsen der Kommandozeile. Es muss entweder ein TrustStore für Root-Zertifikate angegeben werden (Option t) oder auf die Prüfung von Zertifikaten verzichtet werden (Option -o)");
            }

            if (cmd.hasOption("t")) {
                trustCertPath = cmd.getOptionValue("t");
                try {
                    trustedCert = CertificateHelper.loadCertificate(Path.of(trustCertPath));
                } catch (CertificateLoadException | IOException e) {
                    e.printStackTrace();
                }
            }

            if (cmd.hasOption("v")) {
                String stringOfValidators = cmd.getOptionValue("v");
                String[] listOfValidatorsString = stringOfValidators.split(",");

                try {
                    for (String valString : listOfValidatorsString) {
                        Class<?> clazz = Class.forName(valString);
                        Constructor<?> ctor = clazz.getConstructor();
                        Validator val = (Validator) ctor.newInstance();
                        listOfValidators.add(val);
                    }
                } catch (InstantiationException | InvocationTargetException | NoSuchMethodException | IllegalAccessException | ClassNotFoundException e) {
                    logger.error("Fehler beim Initialisieren des aussgewählten Validators.");
                    e.printStackTrace();
                }

            } else {
                listOfValidators.add(new CertificateFileNameValidator());
                listOfValidators.add(new TimeStampValidator());
                listOfValidators.add(new SignatureCounterValidator());
                listOfValidators.add(new LogMessageSignatureValidator());
            }

            AggregatedValidator validator = new AggregatedValidator();
            for (Validator val : listOfValidators) {
                validator.add(val);
            }

            if (cmd.hasOption("t")) {
                validator.add(new CertificateValidator(Collections.singleton(trustedCert)));
            }

            Collection<LogMessageArchive> tarArchives = new ArrayList<>();
            ValidationResult valResults = null;
            ArrayList<File> inputFiles = new ArrayList<>();

            //We are creating the files from the input strings first to make sure that they are existing
            for (String inputFileName : cmd.getArgs()) {
                File inputFile = new File(inputFileName);
                if (inputFile.exists()) inputFiles.add(inputFile);
                else {
                    logger.error("File: " + inputFileName + " is not existing");
                    logger.error("Program will exit now.");
                    System.exit(1);
                }
            }
            for (File inputFile : inputFiles) {
                LogMessageArchiveImplementation tar = new LogMessageArchiveImplementation(inputFile);
                tarArchives.add(tar);
                valResults = validator.validate(tar);
            }

            if (cmd.hasOption("g")) {
                String reportPath = cmd.getOptionValue("g");
                String fileSuffixOfReportPath = reportPath.substring(reportPath.lastIndexOf(".") + 1);
                if ((!fileSuffixOfReportPath.equals("html")) && (!fileSuffixOfReportPath.equals("htm"))) {
                    logger.error("The value of option g has to end on .html or .htm.");
                    System.exit(1);
                }
                HtmlReporter htmlReporter = new HtmlReporter();
                File reportFile = new File(cmd.getOptionValue("g"));
                Files.writeString(reportFile.toPath(), htmlReporter.createReport(tarArchives, valResults, skipLegitLogMessagesInReporting));

            } else {
                TextReporter textReporter = new TextReporter();
                System.out.println(textReporter.createReport(tarArchives, valResults, skipLegitLogMessagesInReporting));
            }

        } catch (BadFormatForTARException e) {
            e.printStackTrace();
        } catch (ParseException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Reporter.ReporterException e) {
            e.printStackTrace();
        }

    }
}
