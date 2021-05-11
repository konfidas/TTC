package de.konfidas.ttc.validation;

public class FileNameValidator extends AggregatedValidator{

    public FileNameValidator(){
        this.add(new CertificateFileNameValidator());
        this.add(new LogMessageFileNameValidator());
    }
}
