package de.fau.fuzzing.logparser.parser;

import java.util.ArrayList;
import java.util.List;

public class LogException
{
    private final List<String> stacktrace = new ArrayList<>();
    private transient String component;
    private transient boolean crash;
    private String type;
    private String message;
    private String cause;

    public boolean isCrash()
    {
        return crash;
    }

    public void setCrash(boolean crash)
    {
        this.crash = crash;
    }

    public String getType()
    {
        return type;
    }

    public void setType(String type)
    {
        this.type = type;
    }

    public String getCause()
    {
        return cause;
    }

    public void setCause(String cause)
    {
        this.cause = cause;
    }

    public String getMessage()
    {
        return message;
    }

    public void setMessage(String message)
    {
        this.message = message;
    }

    public List<String> getStacktrace()
    {
        return stacktrace;
    }

    public void addStacktraceLine(String line)
    {
        stacktrace.add(line);
    }

    public String getComponent()
    {
        return component;
    }

    public void setComponent(String component)
    {
        this.component = component;
    }
}
