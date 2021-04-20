package de.konfidas.ttc.messages.logtime;

public class GeneralizedLogTime extends LogTime {
    String time;

    public GeneralizedLogTime(String time) {
        this.time = time;
    }

    @Override
    public String toString(){
        return time;
    }

    @Override
    public Type getType() {
        return Type.GENERALIZED;
    }
}
