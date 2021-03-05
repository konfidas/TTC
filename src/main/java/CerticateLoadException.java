/**
 * Diese Exception wird aus der Methode loadCertificate geworfen. Sie zeigt an,
 * dass beim Laden des Zertifikats ein Fehler aufgetreten ist. Die Exception enthält
 * eine message mit weitere Infos und eine innerException, die auf die Ursache des Fehlers zeigt
 */

public class CerticateLoadException extends Exception{

    private String message;
    private Exception innerExcpetion;

    public CerticateLoadException(String message, Exception innerExcpetion){
        this.message = message;
        this.innerExcpetion = innerExcpetion;
    }
    public Exception getInnerExcpetion() {
        return innerExcpetion;
    }

    @Override
    public String getMessage() {
        return message;
    }

}
