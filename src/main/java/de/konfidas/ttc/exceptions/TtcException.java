package de.konfidas.ttc.exceptions;

public class TtcException extends Exception{
    String message;
    Exception reason;

    TtcException(String message, Exception reason){
        this.message = message;
        this.reason = reason;
    }

    @Override
    public String getMessage(){
        return message;
    }

    public Exception getReason(){
        return reason;
    }

    @Override
    public String toString(){
        if(reason != null) {
            return message + ", reason: " + reason.toString();
        }else{
            return message;
        }
    }
}
