package de.konfidas.ttc.messages.systemlogs;

import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.messages.SystemLogMessage;
import de.konfidas.ttc.utilities.DLTaggedObjectConverter;
import org.bouncycastle.asn1.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Collections;
import java.util.List;
import java.util.ListIterator;
import java.util.NoSuchElementException;


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
 * ║ parameters            │ 0x83 │ OCTECTSTRING                                                  │ c          ║
 * ╚═══════════════════════╧══════╧══════════════════════════════════╧═════════════════════════════════════════╝
 * </pre>
 */
public class ConfigureLoggingSystemLogMessage extends SystemLogMessage {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);



    DLTaggedObject componentName;
    DLTaggedObject result;
    DLTaggedObject parameters;
    List<ASN1Primitive> loggingParameter;


    String componentNameAsString;
    Boolean resultAsBoolean;
//    String reasonForFailureAsString;



    public ConfigureLoggingSystemLogMessage(byte[] content, String filename) throws BadFormatForLogMessageException {
        super(content, filename);
    }


    @Override
        protected void parseSystemOperationDataContent(ASN1InputStream stream) throws SystemLogParsingException, IOException {

        ASN1Primitive systemOperationData = stream.readObject();
        if (!(systemOperationData instanceof ASN1Sequence)) throw new SystemLogParsingException("Fehler beim Parsen des systemOperationDataContent");

        List<ASN1Primitive> systemOperationDataAsAsn1List = Collections.list(((ASN1Sequence) systemOperationData).getObjects());
        ListIterator<ASN1Primitive> systemOperationDataIterator = systemOperationDataAsAsn1List.listIterator();

        try {
            //componentName einlesen
            DLTaggedObject nextElement = (DLTaggedObject) systemOperationDataAsAsn1List.get(systemOperationDataIterator.nextIndex());
            if (nextElement.getTagNo() != 1) throw new SystemLogParsingException("Fehler beim Parsen des systemOperationDataContent. Das Pflichtfeld componentName wurde nicht gefunden");

            this.componentName = (DLTaggedObject) systemOperationDataIterator.next();
            this.componentNameAsString = DLTaggedObjectConverter.dLTaggedObjectToString(this.componentName);

            //result
             nextElement = (DLTaggedObject) systemOperationDataAsAsn1List.get(systemOperationDataIterator.nextIndex());
            if (nextElement.getTagNo() != 3) throw new SystemLogParsingException("Fehler beim Parsen des systemOperationDataContent. Das Pflichtfeld result wurde nicht gefunden");

            this.result = (DLTaggedObject) systemOperationDataIterator.next();
            this.resultAsBoolean = DLTaggedObjectConverter.dLTaggedObjectToBoolean(this.result);


            //parameters
            nextElement = (DLTaggedObject) systemOperationDataAsAsn1List.get(systemOperationDataIterator.nextIndex());
            if (nextElement.getTagNo() != 3) throw new SystemLogParsingException("Fehler beim Parsen des systemOperationDataContent. Das Pflichtfeld parameters wurde nicht gefunden");

            this.parameters = (DLTaggedObject) systemOperationDataIterator.next();


            //parameters is a Sequence in itself. Parsing follows

            if (this.parameters.getObject() instanceof ASN1Sequence) {

                List<ASN1Primitive> parametersAsASN1List = Collections.list(((ASN1Sequence) this.parameters.getObject()).getObjects());
                ListIterator<ASN1Primitive> parametersSetIterator = parametersAsASN1List.listIterator();

                while (parametersSetIterator.hasNext()) {
                    ASN1Primitive loggingParameter = parametersSetIterator.next();
                    this.loggingParameter.add(loggingParameter);
                }

                for (ASN1Primitive loggingParameter :this.loggingParameter) {
                    if (!(loggingParameter instanceof ASN1Sequence)) {
                        throw new SystemLogParsingException("Fehler beim Parsen des loggingParameter. Der Eintrag sollte vom Typ ASNSequence sein.");

                    } else{
                        List<ASN1Primitive> parametersContentAsASN1List = Collections.list(((ASN1Sequence) loggingParameter).getObjects());
                        ListIterator<ASN1Primitive> parametersContentSetIterator = parametersContentAsASN1List.listIterator();
//TODO HIER WEITER 

                    }
                }


            }
            else throw new SystemLogParsingException("Fehler beim Parsen des systemOperationDataContent. Das Pflichtfeld parameters startet nicht mit einer Sequenz");




        }
        catch (NoSuchElementException ex){
            throw new SystemLogParsingException("Fehler beim Parsen des systemOperationDataContent. Vorzeitiges Ende von systemOperationData", ex);
        }
    }


}