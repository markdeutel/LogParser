package de.fau.fuzzing.logparser.parser;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.SetMultimap;

public class ApplicationLog
{
    private final SetMultimap<String, LogException> crashes = HashMultimap.create();
    private final SetMultimap<String, LogException> exceptions = HashMultimap.create();
    private String packageName;
    private int iterations, receivers, services, activities;

    public String getPackageName()
    {
        return packageName;
    }

    public void setPackageName(String packageName)
    {
        this.packageName = packageName;
    }

    public int getIterations()
    {
        return iterations;
    }

    public void setIterations(int iterations)
    {
        this.iterations = iterations;
    }

    public int getReceivers()
    {
        return receivers;
    }

    public void setReceivers(int receivers)
    {
        this.receivers = receivers;
    }

    public int getServices()
    {
        return services;
    }

    public void setServices(int services)
    {
        this.services = services;
    }

    public int getActivities()
    {
        return activities;
    }

    public void setActivities(int activities)
    {
        this.activities = activities;
    }

    public SetMultimap<String, LogException> getCrashes()
    {
        return crashes;
    }

    public void putCrash(String componentName, LogException crash)
    {
        crashes.put(componentName, crash);
    }

    public SetMultimap<String, LogException> getExceptions()
    {
        return exceptions;
    }

    public void putException(String componentName, LogException exception)
    {
        exceptions.put(componentName, exception);
    }
}
