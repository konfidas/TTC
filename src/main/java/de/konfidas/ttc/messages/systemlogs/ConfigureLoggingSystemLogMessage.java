package de.konfidas.ttc.messages.systemlogs;

import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.messages.SystemLogMessage;
import de.konfidas.ttc.utilities.DLTaggedObjectConverter;
import org.bouncycastle.asn1.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.*;


/**
 * Diese Klasse repräsentiert eine configureLogging Message. Dabei werden in der Methode
 * parseSystemOperationDataContent die folgenden Elemente aus systemOperationData geparst
 * <pre>
 * ╔═══════════════════════╤══════╤═══════════════════════════════════════════════════════════════╤════════════╗
 * ║ Data field            │ Tag  │ Data Type                                                     │ Mandatory? ║
 * ╠═══════════════════════╪══════╪═══════════════════════════════════════════════════════════════╪════════════╣
 * ║ componentName         │ 0x81 │ PrintableString                                               │ m          ║
 * ╟───────────────────────┼──────┼───────────────────────────────────────────────────────────────┼────────────╢
 * ║ result                │ 0x82 │ Boolean                                                       │ m          ║
 * ╟───────────────────────┼──────┼───────────────────────────────────────────────────────────────┼────────────╢
 * ║ parameters            │ 0x83 │ OCTET STRING                                                  │ c          ║
 * ╚═══════════════════════╧══════╧═══════════════════════════════════════════════════════════════╧════════════╝
 * </pre>
 */
public class ConfigureLoggingSystemLogMessage extends SystemLogMessage {
    static final Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);


    static Locale locale = new Locale("de", "DE");//NON-NLS
    static ResourceBundle properties = ResourceBundle.getBundle("ttc", locale);//NON-NLS


    DLTaggedObject componentName;
    DLTaggedObject result;
    DLTaggedObject parameters;


    String componentNameAsString;
    Boolean resultAsBoolean;

    ArrayList<LoggingParameter> loggingParameterSet;

    static class LoggingParameter {
        final String eventName;
        final Boolean enabled;

        public LoggingParameter(final String eventName, final Boolean enabled) {
            this.eventName = eventName;
            this.enabled = enabled;
        }
    }


    public ConfigureLoggingSystemLogMessage(byte[] content, String filename) throws BadFormatForLogMessageException {
        super(content, filename);

    }


    @Override
    protected void parseSystemOperationDataContent(ASN1InputStream stream) throws IOException {

        final ASN1Primitive systemOperationData = stream.readObject();
        if (!(systemOperationData instanceof ASN1Sequence)) {
            this.allErrors.add(new SystemLogParsingError(properties.getString("de.konfidas.ttc.messages.systemlogs.errorParsingSystemOperationDataContent")));
        }

        final List<ASN1Primitive> systemOperationDataAsAsn1List = Collections.list(((ASN1Sequence) systemOperationData).getObjects());
        final ListIterator<ASN1Primitive> systemOperationDataIterator = systemOperationDataAsAsn1List.listIterator();

        try {
            //componentName einlesen
            DLTaggedObject nextElement = (DLTaggedObject) systemOperationDataAsAsn1List.get(systemOperationDataIterator.nextIndex());
            if (nextElement.getTagNo() != 1) this.allErrors.add(new SystemLogParsingError(properties.getString("de.konfidas.ttc.messages.systemlogs.errorComonentNameNotFound")));

            this.componentName = (DLTaggedObject) systemOperationDataIterator.next();
            this.componentNameAsString = DLTaggedObjectConverter.dLTaggedObjectToString(this.componentName);

            //result
            nextElement = (DLTaggedObject) systemOperationDataAsAsn1List.get(systemOperationDataIterator.nextIndex());
            if (nextElement.getTagNo() != 2) {
                this.allErrors.add(new SystemLogParsingError(properties.getString("de.konfidas.ttc.messages.systemlogs.errorResultNotFound")));
            }

            this.result = (DLTaggedObject) systemOperationDataIterator.next();
            this.resultAsBoolean = DLTaggedObjectConverter.dLTaggedObjectToBoolean(this.result);

            this.loggingParameterSet = new ArrayList<>();

            //parameters
            nextElement = (DLTaggedObject) systemOperationDataAsAsn1List.get(systemOperationDataIterator.nextIndex());
            if (nextElement.getTagNo() != 3) this.allErrors.add(new SystemLogParsingError(properties.getString("de.konfidas.ttc.messages.systemlogs.errorParametersNotFound")));

            this.parameters = (DLTaggedObject) systemOperationDataIterator.next();

            if (this.parameters.getObject() instanceof ASN1OctetString) {
                final var parameterOctetString = ASN1OctetString.getInstance(this.parameters.getObject());

                final var parametersSequence = ASN1Sequence.getInstance(parameterOctetString.getOctets());

                ArrayList<ASN1Sequence> parametersAsASN1List = Collections.list(parametersSequence.getObjects());

                for (ASN1Sequence parameter : parametersAsASN1List) {
                    final List<ASN1Primitive> loggingParameters = Collections.list(parameter.getObjects());
                    final ListIterator<ASN1Primitive> parameterIterator = loggingParameters.listIterator();

                    nextElement = (DLTaggedObject) loggingParameters.get(parameterIterator.nextIndex());
                    if (nextElement.getTagNo() != 0) {
                        this.allErrors.add(new SystemLogParsingError(properties.getString("de.konfidas.ttc.messages.systemlogs.errorEventNameNotFound")));
                    }

                    final var eventNameTaggedObject = (DLTaggedObject) parameterIterator.next();
                    final String eventName = DLTaggedObjectConverter.dLTaggedObjectToString(eventNameTaggedObject);

                    nextElement = (DLTaggedObject) loggingParameters.get(parameterIterator.nextIndex());
                    if (nextElement.getTagNo() != 1) {
                        this.allErrors.add(new SystemLogParsingError(properties.getString("de.konfidas.ttc.messages.systemlogs.errorEnabledNotFound")));
                    }

                    final var enabledTaggedObject = (DLTaggedObject) parameterIterator.next();
                    final Boolean enabled = DLTaggedObjectConverter.dLTaggedObjectToBoolean(enabledTaggedObject);

                    if (parameterIterator.hasNext()) {
                        this.allErrors.add(new SystemLogParsingError(properties.getString("de.konfidas.ttc.messages.systemlogs.errorLoggingParameterUnknownTag")));
                    }

                    final var newLoggingParameter = new LoggingParameter(eventName, enabled);
                    this.loggingParameterSet.add(newLoggingParameter);
                }
            } else {
                this.allErrors.add(new SystemLogParsingError(properties.getString("de.konfidas.ttc.messages.systemlogs.errorParametersDoesNotStartWithOctetString")));
            }
        } catch (NoSuchElementException ex) {
            this.allErrors.add(new SystemLogParsingError(properties.getString("de.konfidas.ttc.messages.systemlogs.errorEarlyEndOfSystemOperationData"), ex));
        }
    }
}
