package de.konfidas.ttc.exceptions;

public class TtcException extends Exception{
    protected TtcException(String message, Throwable cause){
        super(message, cause);
    }

    @Override
    public String toString(){
        if(this.getCause() != null) {
            return getMessage() + ", cause: " + getCause().toString();
        }else{
            return getMessage();
        }
    }
}
