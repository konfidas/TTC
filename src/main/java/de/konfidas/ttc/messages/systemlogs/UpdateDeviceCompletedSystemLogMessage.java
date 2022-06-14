package de.konfidas.ttc.messages.systemlogs;

import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.messages.SystemLogMessage;
import de.konfidas.ttc.utilities.DLTaggedObjectConverter;
import org.bouncycastle.asn1.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.util.*;


/**
 * Diese Klasse repräsentiert eine updateDeviceCompletedSystemLog Message. Dabei werden in der Methode
 * parseSystemOperationDataContent die folgenden Elemente aus systemOperationData geparst
 * <pre>
 * ╔═══════════════════════╤══════╤═══════════════════════════════════════════════════════════════╤════════════╗
 * ║ Data field            │ Tag  │ Data Type                                                     │ Mandatory? ║
 * ╠═══════════════════════╪══════╪═══════════════════════════════════════════════════════════════╪════════════╣
 * ║ updateResult          │ 0x81 │ ENUMERATED {ok (0), failed (1), partlyFailed(2)}              │ m          ║
 * ╟───────────────────────┼──────┼───────────────────────────────────────────────────────────────┼────────────╢
 * ║ reasonForFailure      │ 0x82 │ PrintableString                                               │ c          ║
 * ╟───────────────────────┼──────┼───────────────────────────────────────────────────────────────┼────────────╢
 * ║ newVersion            │ 0x83 │ OCTET STRING                                                  │ m          ║
 * ╚═══════════════════════╧══════╧═══════════════════════════════════════════════════════════════╧════════════╝
 * </pre>
 *
 * newVersion
 * <pre>
 * ╔════════════════════════════╤══════╤═══════════════════════════════════════════════════════════════╤════════════╗
 * ║ Data field                 │ Tag  │ Data Type                                                     │ Mandatory? ║
 * ╠════════════════════════════╪══════╪═══════════════════════════════════════════════════════════════╪════════════╣
 * ║ DeviceInformationSet       │ 0x30 │ SEQUENCE OF                                                   │ m          ║
 * ╟────────────────────────────┼──────┼───────────────────────────────────────────────────────────────┼────────────╢
 * ║    componentInformationSet │ 0x30 │ SEQUENCE                                                      │ m          ║
 * ╟────────────────────────────┼──────┼───────────────────────────────────────────────────────────────┼────────────╢
 * ║        componentName       │ 0x80 │ PrintableString                                               │ m          ║
 * ╟────────────────────────────┼──────┼───────────────────────────────────────────────────────────────┼────────────╢
 * ║        manufacturer        │ 0x81 │ PrintableString                                               │ m          ║
 * ╟────────────────────────────┼──────┼───────────────────────────────────────────────────────────────┼────────────╢
 * ║        model               │ 0x82 │ PrintableString                                               │ m          ║
 * ╟────────────────────────────┼──────┼───────────────────────────────────────────────────────────────┼────────────╢
 * ║        version             │ 0x83 │ PrintableString                                               │ m          ║
 * ╟────────────────────────────┼──────┼───────────────────────────────────────────────────────────────┼────────────╢
 * ║        certificationId     │ 0x84 │ PrintableString                                               │ o          ║
 * ╚════════════════════════════╧══════╧═══════════════════════════════════════════════════════════════╧════════════╝
 * </pre>
 */
public class UpdateDeviceCompletedSystemLogMessage extends SystemLogMessage {
    static final Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    static Locale locale = new Locale("de", "DE"); //NON-NLS
    static ResourceBundle properties = ResourceBundle.getBundle("ttc", locale);//NON-NLS

    DLTaggedObject updateResult;
    DLTaggedObject reasonForFailure;
    DLTaggedObject newVersion;

    BigInteger updateResultAsBigInteger;
    String reasonForFailureAsString;
    ArrayList<ComponentInformationSet> deviceInformationSet;

    static final ArrayList<String> requiredComponentNames = new ArrayList<>(Arrays.asList("device", "CSP", "SMAERS", "storage"));

    static class ComponentInformationSet {
        String componentName;
        String manufacturer;
        String model;
        String version;
        String certificationId;
    }

    public UpdateDeviceCompletedSystemLogMessage(byte[] content, String filename) throws BadFormatForLogMessageException {
        super(content, filename);
    }

    @Override
    protected void parseSystemOperationDataContent(ASN1InputStream stream) throws IOException {

        ASN1Primitive systemOperationData = stream.readObject();
        if (!(systemOperationData instanceof ASN1Sequence))
            this.allErrors.add(new SystemLogParsingError(properties.getString("de.konfidas.ttc.messages.systemlogs.errorParsingSystemOperationDataContent")));

        List<ASN1Primitive> systemOperationDataAsAsn1List = Collections.list(((ASN1Sequence) systemOperationData).getObjects());
        ListIterator<ASN1Primitive> systemOperationDataIterator = systemOperationDataAsAsn1List.listIterator();

        try {
            //read updateResult
            DLTaggedObject nextElement = (DLTaggedObject) systemOperationDataAsAsn1List.get(systemOperationDataIterator.nextIndex());
            if (nextElement.getTagNo() != 1) {
                this.allErrors.add(new SystemLogParsingError(properties.getString("de.konfidas.ttc.messages.systemlogs.errorParsingSystemOperationDataUpdateResultNotFound")));
            }

            this.updateResult = (DLTaggedObject) systemOperationDataIterator.next();
            this.updateResultAsBigInteger = DLTaggedObjectConverter.dLTaggedObjectToASN1Integer(this.updateResult).getValue();

            nextElement = (DLTaggedObject) systemOperationDataAsAsn1List.get(systemOperationDataIterator.nextIndex());

            //read reasonForFailure
            if (nextElement.getTagNo() == 2) {
                this.reasonForFailure = (DLTaggedObject) systemOperationDataIterator.next();
                this.reasonForFailureAsString = DLTaggedObjectConverter.dLTaggedObjectToString(this.reasonForFailure);
            }

            nextElement = (DLTaggedObject) systemOperationDataAsAsn1List.get(systemOperationDataIterator.nextIndex());

            //read newVersion
            if (nextElement.getTagNo() != 3) {
                this.allErrors.add(new SystemLogParsingError(properties.getString("de.konfidas.ttc.messages.systemlogs.errorParsingSystemOperationDataNewVersionNotFound")));
            }

            this.newVersion = (DLTaggedObject) systemOperationDataIterator.next();

            if (this.newVersion.getObject() instanceof ASN1OctetString) {
                final ASN1OctetString newVersionAsOctetString = ASN1OctetString.getInstance(this.newVersion.getObject());

                this.parseDeviceInformationSet(ASN1Sequence.getInstance(newVersionAsOctetString.getOctets()));

                this.validateDeviceInformationSet();
            } else {
                this.allErrors.add(new SystemLogParsingError(properties.getString("de.konfidas.ttc.messages.systemlogs.errorParsingSystemOperationDataContentNewVersionIsNotOctetString")));
            }
        } catch (NoSuchElementException ex) {
            this.allErrors.add(new SystemLogParsingError(properties.getString("de.konfidas.ttc.messages.systemlogs.errorParsingSystemOperationDataContentEarlyEnd"), ex));
        }
    }

    private void parseDeviceInformationSet(ASN1Sequence deviceInformationSet) {
        List<ASN1Primitive> deviceInformationSetAsASN1List = Collections.list(deviceInformationSet.getObjects());
        ListIterator<ASN1Primitive> deviceInformationSetIterator = deviceInformationSetAsASN1List.listIterator();

        if (!deviceInformationSetIterator.hasNext()) {
            this.allErrors.add(new SystemLogParsingError(properties.getString("de.konfidas.ttc.messages.systemlogs.errorDeviceInformationSetEndedEarly")));
        }

        this.deviceInformationSet = new ArrayList<>();

        while (deviceInformationSetIterator.hasNext()) {
            List<ASN1Primitive> componentInformationSetAsASN1 = Collections.list(((ASN1Sequence) deviceInformationSetAsASN1List.get(deviceInformationSetIterator.nextIndex())).getObjects());
            ListIterator<ASN1Primitive> componentInformationSetIterator = componentInformationSetAsASN1.listIterator();

            var component = new ComponentInformationSet();

            //componentName
            var nextElement = (DLTaggedObject) componentInformationSetAsASN1.get(componentInformationSetIterator.nextIndex());
            if (nextElement.getTagNo() != 0) {
                this.allErrors.add(new SystemLogParsingError(properties.getString("de.konfidas.ttc.messages.systemlogs.errorParsingSystemOperationDataComponentNameNotFound")));
            }
            DLTaggedObject componentName = (DLTaggedObject) componentInformationSetIterator.next();
            component.componentName = DLTaggedObjectConverter.dLTaggedObjectToString(componentName);

            //manufacturer
            nextElement = (DLTaggedObject) componentInformationSetAsASN1.get(componentInformationSetIterator.nextIndex());
            if (nextElement.getTagNo() != 1) {
                this.allErrors.add(new SystemLogParsingError(properties.getString("de.konfidas.ttc.messages.systemlogs.errorParsingSystemOperationDataManufacturerNotFound")));
            }
            DLTaggedObject manufacturer = (DLTaggedObject) componentInformationSetIterator.next();
            component.manufacturer = DLTaggedObjectConverter.dLTaggedObjectToString(manufacturer);

            //model
            nextElement = (DLTaggedObject) componentInformationSetAsASN1.get(componentInformationSetIterator.nextIndex());
            if (nextElement.getTagNo() != 2) {
                this.allErrors.add(new SystemLogParsingError(properties.getString("de.konfidas.ttc.messages.systemlogs.errorParsingSystemOperationDataModelNotFound")));
            }
            DLTaggedObject model = (DLTaggedObject) componentInformationSetIterator.next();
            component.model = DLTaggedObjectConverter.dLTaggedObjectToString(model);

            //version
            nextElement = (DLTaggedObject) componentInformationSetAsASN1.get(componentInformationSetIterator.nextIndex());
            if (nextElement.getTagNo() != 3) {
                this.allErrors.add(new SystemLogParsingError(properties.getString("de.konfidas.ttc.messages.systemlogs.errorParsingSystemOperationDataVersionNotFound")));
            }
            DLTaggedObject version = (DLTaggedObject) componentInformationSetIterator.next();
            component.version = DLTaggedObjectConverter.dLTaggedObjectToString(version);

            //certificationId
            if (componentInformationSetIterator.hasNext()) {
                nextElement = (DLTaggedObject) componentInformationSetAsASN1.get(componentInformationSetIterator.nextIndex());
                if (nextElement.getTagNo() != 4) {
                    this.allErrors.add(new SystemLogParsingError(properties.getString("de.konfidas.ttc.messages.systemlogs.errorParsingSystemOperationDataUnknownTag")));
                }
                DLTaggedObject certificationId = (DLTaggedObject) componentInformationSetIterator.next();
                component.certificationId = DLTaggedObjectConverter.dLTaggedObjectToString(certificationId);
            }

            if (componentInformationSetIterator.hasNext()) {
                this.allErrors.add(new SystemLogParsingError(properties.getString("de.konfidas.ttc.messages.systemlogs.errorParsingSystemOperationDataTooLong")));
            }

            this.deviceInformationSet.add(component);

            deviceInformationSetIterator.next();
        }
    }

    /*
        MUST contain version information about all components that together comprise the TSE.
        That means: at least TSE, storage, SMAERS, and CSP.
     */
    private void validateDeviceInformationSet() {
        if (this.deviceInformationSet.size() < 4) {
            this.allErrors.add(new SystemLogParsingError(properties.getString("de.konfidas.ttc.messages.systemlogs.errorParsingSystemOperationDataDeviceInformationSetTooShort")));
        }

        this.deviceInformationSet.forEach(component -> {
            if (!this.requiredComponentNames.contains(component.componentName)) {
                this.allErrors.add(new SystemLogParsingError(properties.getString("de.konfidas.ttc.messages.systemlogs.errorParsingSystemOperationDataComponentMissing")));
            }
        });
    }
}
