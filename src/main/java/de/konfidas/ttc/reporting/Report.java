package de.konfidas.ttc.reporting;

import java.util.ArrayList;
import java.util.List;

/**
 * Generic Class for reporting. The class represents a tree structure of elements
 * that make up a report
 * @param <T> The type of the data to be reported
 */
public class Report<T> {
    T data = null;
    String name;
    List<Report<?>> children = new ArrayList<>();
    Report<?> parent = null;

    public Report(String name, T data) {
        this.data = data;
        this.name= name;
    }

    public Report<?> addChild(Report<?> child) {
        child.setParent(this);
        this.children.add(child);
        return child;
    }

    public void addChildren(List<Report<?>> children) {
        children.forEach(each -> each.setParent(this));
        this.children.addAll(children);
    }

    public List<Report<?>> getChildren() {
        return children;
    }

    public T getData() {
        return data;
    }

    public void setData(T data) {
        this.data = data;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    void setParent(Report<?> parent) {
        this.parent = parent;
    }

    public Report<?> getParent() {
        return parent;
    }


}
