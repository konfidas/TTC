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
    static Locale locale = new Locale("de", "DE"); //NON-NLS
    static ResourceBundle properties = ResourceBundle.getBundle("ttc",locale);//NON-NLS

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        Options options = new Options();

        options.addOption("t", "trustAnker", true, properties.getString("de.konfidas.ttt.help_rootCA"));//NON-NLS
        options.addOption("h", "help", false, properties.getString("de.konfidas.ttc.help_printHelp"));//NON-NLS
        options.addOption("n", "noCertCheck", false, properties.getString("de.konfidas.ttc.help_omitRootCaCheck"));//NON-NLS
        options.addOption("d", "debug", false, properties.getString("de.konfidas.ttc.help_setDebugging"));//NON-NLS
        options.addOption("e", "errorsOnly", false, properties.getString("de.konfidas.ttc.help_errorsOnly"));//NON-NLS
        options.addOption("g", "generateHtmlReport", true, properties.getString("de.konfidas.ttc.help_htmlOut"));//NON-NLS
        options.addOption("v", "validator", true, properties.getString("de.konfidas.ttc.help_selectValidators"));//NON-NLS

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
            if (cmd.hasOption("d")) {//NON-NLS
                logger.setLevel(DEBUG);
            }
            if (cmd.hasOption("h")) {//NON-NLS
                HelpFormatter formatter = new HelpFormatter();
                formatter.setWidth(120);
                formatter.printHelp("ttc", options );//NON-NLS
                System.exit(0);
            }
            if (cmd.hasOption("e")) {//NON-NLS
                skipLegitLogMessagesInReporting = true;
            }

            if (!(cmd.hasOption("t") || cmd.hasOption("n"))) {//NON-NLS
                System.err.println(properties.getString("de.konfidas.ttc.errorParsingCommandEitherRootMustBePresentOrOptionChosen"));
            }

            if (cmd.hasOption("t")) {//NON-NLS
                trustCertPath = cmd.getOptionValue("t");//NON-NLS
                try {
                    trustedCert = CertificateHelper.loadCertificate(Path.of(trustCertPath));
                } catch (CertificateLoadException | IOException e) {
                    e.printStackTrace();
                }
            }

            if (cmd.hasOption("v")) {//NON-NLS
                String stringOfValidators = cmd.getOptionValue("v");//NON-NLS
                String[] listOfValidatorsString = stringOfValidators.split(",");//NON-NLS

                try {
                    for (String valString : listOfValidatorsString) {
                        Class<?> clazz = Class.forName(valString);
                        Constructor<?> ctor = clazz.getConstructor();
                        Validator val = (Validator) ctor.newInstance();
                        listOfValidators.add(val);
                    }
                } catch (InstantiationException | InvocationTargetException | NoSuchMethodException | IllegalAccessException | ClassNotFoundException e) {
                    logger.error(properties.getString("de.konfidas.ttc.errorInitializeValidator"));//NON-NLS
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

            if (cmd.hasOption("t")) {//NON-NLS
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
                    logger.error(String.format(properties.getString("de.konfidas.ttc.FileNotExisting"), inputFile));
                    logger.error(properties.getString("de.konfidas.tts.programWillExit"));
                    System.exit(1);
                }
            }
            for (File inputFile : inputFiles) {
                LogMessageArchiveImplementation tar = new LogMessageArchiveImplementation(inputFile);
                tarArchives.add(tar);
                valResults = validator.validate(tar);
            }

            if (cmd.hasOption("g")) {//NON-NLS
                String reportPath = cmd.getOptionValue("g");//NON-NLS
                String fileSuffixOfReportPath = reportPath.substring(reportPath.lastIndexOf(".") + 1);//NON-NLS
                if ((!fileSuffixOfReportPath.equals("html")) && (!fileSuffixOfReportPath.equals("htm"))) {//NON-NLS
                    logger.error(properties.getString("de.konfidas.ttc.optionGWrongEnding"));//NON-NLS
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
