package de.konfidas.ttc.reporting;

import java.util.ArrayList;
import java.util.List;

/**
 * Generic Class for reporting. The class represents a tree structure of elements
 * that make up a report
 * @param <T> The type of the data to be reported
 */
public class Report<T> {


    private T data = null;
    private String name;

    private List<Report<T>> children = new ArrayList<>();

    private Report<T> parent = null;

    public Report(String name, T data) {
        this.data = data;
        this.name= name;
    }

    public Report<T> addChild(Report<T> child) {
        child.setParent(this);
        this.children.add(child);
        return child;
    }

    public void addChildren(List<Report<T>> children) {
        children.forEach(each -> each.setParent(this));
        this.children.addAll(children);
    }

    public List<Report<T>> getChildren() {
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

    private void setParent(Report<T> parent) {
        this.parent = parent;
    }

    public Report<T> getParent() {
        return parent;
    }


}
