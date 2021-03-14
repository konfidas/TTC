package de.konfidas.ttc.utilities;

import de.konfidas.ttc.exceptions.CertificateLoadException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;

public class CertificateHelper {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);


    // found at https://stackoverflow.com/questions/28172710/java-compact-representation-of-ecc-publickey
    public static byte[] publicKeyToUncompressedPoint(final ECPublicKey publicKey) {

        int keySizeBytes = (publicKey.getParams().getOrder().bitLength() + Byte.SIZE - 1)
                / Byte.SIZE;

        final byte[] uncompressedPoint = new byte[1 + 2 * keySizeBytes];
        int offset = 0;
        uncompressedPoint[offset++] = 0x04;

        final byte[] x = publicKey.getW().getAffineX().toByteArray();
        if (x.length <= keySizeBytes) {
            System.arraycopy(x, 0, uncompressedPoint, offset + keySizeBytes
                    - x.length, x.length);
        } else if (x.length == keySizeBytes + 1 && x[0] == 0) {
            System.arraycopy(x, 1, uncompressedPoint, offset, keySizeBytes);
        } else {
            throw new IllegalStateException("x value is too large");
        }
        offset += keySizeBytes;

        final byte[] y = publicKey.getW().getAffineY().toByteArray();
        if (y.length <= keySizeBytes) {
            System.arraycopy(y, 0, uncompressedPoint, offset + keySizeBytes
                    - y.length, y.length);
        } else if (y.length == keySizeBytes + 1 && y[0] == 0) {
            System.arraycopy(y, 1, uncompressedPoint, offset, keySizeBytes);
        } else {
            throw new IllegalStateException("y value is too large");
        }

        return uncompressedPoint;
    }


    public static X509Certificate loadCertificate(File file) throws CertificateLoadException, IOException {
        return loadCertificate(file.toPath());
    }

    public static X509Certificate loadCertificate(Path path) throws CertificateLoadException, IOException {
        return loadCertificate(Files.readAllBytes(path));
    }

    /**
     * Diese Funktion lädt ein X059Certificat aus einem ByteArray und kümmert sich um die Fehlerbehandlung
     *
     * @param certContent Ein Byte-Array, das das Zertifikat enthält
     * @return das X509Certificate Objekt
     * @throws CertificateLoadException
     */
    public static X509Certificate loadCertificate(byte[] certContent) throws CertificateLoadException {
        X509Certificate cer = null;
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
            InputStream in = new ByteArrayInputStream(certContent);
            cer = (X509Certificate) cf.generateCertificate(in);

            /*******************************************
             ** Prüfen, dass das Zertifikat gültig ist *
             *******************************************/
            cer.checkValidity();

        }
        catch (CertificateExpiredException e) {
            logger.error("Das Zertifikat ist abgelaufen.");
        }
        catch (CertificateNotYetValidException e) {
            logger.error("Das Zertifikat ist noch nicht gültig.");
        }
        catch (java.security.cert.CertificateException e) {
            throw new RuntimeException(e);
        }
        catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return cer;
    }


}
