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
import java.util.HashMap;
import java.util.Locale;

public class LogMessageSignatureVerifier {
    final static Logger logger = LoggerFactory.getLogger(LogMessageSignatureVerifier.class);

    HashMap<String, X509Certificate> certs;

    public LogMessageSignatureVerifier(HashMap<String, X509Certificate> certs){
        this.certs = certs;
    }

    public void verify(LogMessage msg) throws LogMessageVerificationException {
        if (certs == null || certs.isEmpty()) {
            throw new CertificateNotFoundException("No certificate found");
        }
        if (msg == null) {
            throw new LogMessageVerificationException("No message found", null);
        }

        byte[] serial = msg.getSerialNumber();
        X509Certificate cert = certs.get(Hex.encodeHexString(msg.getSerialNumber()).toUpperCase(Locale.ROOT));

        if(cert == null){
            throw new CertificateNotFoundException("failed to identify certificate for serial number "+ Hex.encodeHexString(serial));
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
            logger.info("signature validated successfully");
        } catch (NoSuchProviderException e) {
            throw new LogMessageVerificationException("Bouncy Castle wurde als Provider nicht gefunden", e);
        } catch (NoSuchAlgorithmException e) {
            throw new LogMessageVerificationException("Der Algorithmus wird nicht unterstützt", e);
        } catch (SignatureException e) {
            throw new LogMessageVerificationException("Die Signatur konnte nicht verifiziert werden.", e);
        } catch (InvalidKeyException e) {
            throw new LogMessageVerificationException("Der Schlüssel zur Prüfung der Signatur konnte nicht eingelesen werden.", e);
        }
    }

    public static class CertificateNotFoundException extends LogMessageVerificationException{
        public CertificateNotFoundException(String message) {
            super(message);
        }
    }
}
