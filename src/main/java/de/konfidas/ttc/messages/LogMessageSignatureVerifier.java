package de.konfidas.ttc.messages;

import de.konfidas.ttc.exceptions.LogMessageVerificationException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.AlgorithmNameFinder;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Locale;
import java.util.Map;
import java.util.ResourceBundle;

public class LogMessageSignatureVerifier {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    static Locale locale = new Locale("de", "DE");//NON-NLS
    static ResourceBundle properties = ResourceBundle.getBundle("ttc",locale);//NON-NLS
    final Map<? extends String, ? extends X509Certificate> certs;

    public LogMessageSignatureVerifier(Map<? extends String, ? extends X509Certificate> certs){
        this.certs = certs;
    }

    public void verify(LogMessage msg) throws LogMessageVerificationException {
        if (certs == null || certs.isEmpty()) {
            throw new CertificateNotFoundException(properties.getString("de.konfidas.ttc.messages.noCertificateFound"));
        }
        if (msg == null) {
            throw new LogMessageVerificationException(properties.getString("de.konfidas.ttc.messages.noMessageFound"), null);
        }

        byte[] serial = msg.getSerialNumber();
        X509Certificate cert = certs.get(Hex.encodeHexString(msg.getSerialNumber()).toUpperCase(Locale.ROOT));

        if(cert == null){
            throw new CertificateNotFoundException(String.format(properties.getString("de.konfidas.ttc.messages.failedToIdentifyCertForSerial"), Hex.encodeHexString(serial)));
        }

        try {
            ASN1ObjectIdentifier algoIdentifier = new ASN1ObjectIdentifier(msg.getSignatureAlgorithm());
            AlgorithmNameFinder nameFinder = new DefaultAlgorithmNameFinder();
            String algoName = nameFinder.getAlgorithmName(algoIdentifier);

            Signature st = Signature.getInstance(algoName, BouncyCastleProvider.PROVIDER_NAME);
            st.initVerify(cert.getPublicKey());

            st.update(msg.getDTBS());

            byte[] signatureValue = msg.getSignatureValue();
            st.verify(signatureValue);
            logger.debug("The signature of logMessage {} has been validated successfully.",msg);//NON-NLS
        } catch (NoSuchProviderException e) {
            throw new LogMessageVerificationException(properties.getString("de.konfidas.ttc.messages.bouncyCastleNotFound"), e);
        } catch (NoSuchAlgorithmException e) {
            throw new LogMessageVerificationException(properties.getString("de.konfidas.ttc.messages.algortihmNotSupported"), e);
        } catch (SignatureException e) {
            throw new LogMessageVerificationException(properties.getString("de.konfidas.ttc.messages.signatureCouldNotBeVerified"), e);
        } catch (InvalidKeyException e) {
            throw new LogMessageVerificationException(properties.getString("de.konfidas.ttc.messages.keyForSignatureValidationCouldNotBeRead"), e);
        }
    }

    public static class CertificateNotFoundException extends LogMessageVerificationException{
        public CertificateNotFoundException(String message) {
            super(message);
        }
    }
}
