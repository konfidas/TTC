package de.konfidas.ttc.exceptions;
/**
 * Diese Exception zeigt ein fehlerhaftes TAR-File. Sie wird geworfen, wenn ein TAR-File nicht oder nur mit Fehlern geparst werden konnte.
 */
public class GeneralTARFileError extends TtcException{
    public GeneralTARFileError(String message, Throwable cause){
        super(message,cause);
    }
    public GeneralTARFileError(String message){
        super(message,null);
    }
}

