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

    static Locale locale = new Locale("de", "DE");//NON-NLS
    static ResourceBundle properties = ResourceBundle.getBundle("ttc",locale);//NON-NLS


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
    public ValidationResult validate(LogMessageArchive tar) {
        LinkedList<ValidationException> errors = new LinkedList<>();

        for (X509Certificate cert : tar.getClientCertificates().values()) {
            try {
                logger.debug(properties.getString("de.konfidas.ttc.validation.checkingCert"), cert.getSerialNumber());
                checkCert(cert, trustedCerts, new ArrayList<>(tar.getIntermediateCertificates().values()), crls);
            }catch (Exception e) {
                errors.add(new CertificateValidationException(cert, e));
            }
        }

        return new ValidationResultImpl().append(Collections.singleton(this), errors);
    }

    public void checkCert(X509Certificate certToCheck, Set<TrustAnchor> trustedCerts, List<X509Certificate> intermediateCerts, Collection<CRL> crls) throws
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException, CertPathValidatorException, CertificateException {

        CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);//NON-NLS

        ArrayList<X509Certificate> certs = new ArrayList<>();
        certs.add(certToCheck);
        certs.addAll(intermediateCerts);

        CertPath path = cf.generateCertPath(certs);
        CertPathValidator validator = CertPathValidator.getInstance("PKIX");//NON-NLS

        CertStore crlStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(crls));//NON-NLS

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
            super(String.format(properties.getString("de.konfidas.ttc.validation.validationOfCertificateFailed"), cert.getSerialNumber()), e);
            this.cert = cert;
        }
        public X509Certificate getCert(){return cert;}
    }
}
