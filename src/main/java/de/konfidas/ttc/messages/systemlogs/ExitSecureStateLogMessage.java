package de.konfidas.ttc.messages.systemlogs;

import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.messages.SystemLogMessage;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Locale;
import java.util.ResourceBundle;


/**
 * Diese Klasse repräsentiert eine startAudit Message. systemOperationData Darf keine Daten enthalten

 */
public class ExitSecureStateLogMessage extends SystemLogMessage {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    static Locale locale = new Locale("de", "DE"); //NON-NLS
    static ResourceBundle properties = ResourceBundle.getBundle("ttc",locale);//NON-NLS

    public ExitSecureStateLogMessage(byte[] content, String filename) throws BadFormatForLogMessageException {
        super(content, filename);
    }


    @Override
        protected void parseSystemOperationDataContent(ASN1InputStream stream) throws IOException {

        ASN1Primitive systemOperationData = stream.readObject();
        if (systemOperationData.getEncoded().length>2) this.allErrors.add(new SystemLogParsingError(properties.getString("de.konfidas.ttc.messages.systemlogs.errorSystemOperationDataShallNotContainData")));

    }


}