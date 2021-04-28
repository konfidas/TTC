package de.konfidas.ttc.validation;

import de.konfidas.ttc.exceptions.ValidationException;
import de.konfidas.ttc.tars.LogMessageArchive;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.*;
import java.security.cert.*;
import java.util.*;
import java.util.stream.Collectors;

public class CertificateValidator implements Validator {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    final Set<TrustAnchor> trustedCerts;
    final  Collection<CRL> crls;
    boolean enableRevocationChecking;


    public CertificateValidator(Collection<X509Certificate> trustedCerts){
        this(trustedCerts,new LinkedList<>());
    }

    public void setEnableRevocationChecking(boolean enableRevocationChecking){
        this.enableRevocationChecking = enableRevocationChecking;
    }

    public CertificateValidator(Collection<X509Certificate> trustedCerts,  Collection<CRL> crls){
        this.trustedCerts =  trustedCerts.stream().map(c -> new TrustAnchor(c,null)).collect(Collectors.toSet());
        this.crls = crls;
        enableRevocationChecking = true;
    }

    @Override
    public Collection<ValidationException> validate(LogMessageArchive tar) {
        LinkedList<ValidationException> errors = new LinkedList<>();

        for (X509Certificate cert : tar.getClientCertificates().values()) {
            try {
                logger.debug("Prüfe das Zertifikat mit Seriennummer {} auf Korrektheit und prüfe die zugehörige Zertifikatskette.", cert.getSerialNumber());
                checkCert(cert, trustedCerts, new ArrayList<>(tar.getIntermediateCertificates().values()), crls);
            }catch (Exception e) {
                errors.add(new CertificateValidationException(cert, e));
            }
        }

        return errors;
    }

    public void checkCert(X509Certificate certToCheck, Set<TrustAnchor> trustedCerts, List<X509Certificate> intermediateCerts, Collection<CRL> crls) throws
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException, CertPathValidatorException, CertificateException {

        CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);

        ArrayList<X509Certificate> certs = new ArrayList<>();
        certs.add(certToCheck);
        certs.addAll(intermediateCerts);

        CertPath path = cf.generateCertPath(certs);
        CertPathValidator validator = CertPathValidator.getInstance("PKIX");

        CertStore crlStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(crls));

        PKIXParameters params = new PKIXParameters(trustedCerts);
        //CertStore store = CertStore.getInstance("Collection",new CollectionCertStoreParameters(), BouncyCastleProvider.PROVIDER_NAME);

        //params.addCertStore(store);
        params.setRevocationEnabled(enableRevocationChecking);
        params.addCertStore(crlStore);

        PKIXCertPathValidatorResult r = (PKIXCertPathValidatorResult) validator.validate(path, params);
        logger.debug(r.toString());
    }


    public static class CertificateValidationException extends ValidationException{
        final X509Certificate cert;
        CertificateValidationException(X509Certificate cert, Throwable e) {
            super("Validation of certificate "+ cert.getSerialNumber() +" failed.", e);
            this.cert = cert;
        }
        public X509Certificate getCert(){return cert;}
    }
}
