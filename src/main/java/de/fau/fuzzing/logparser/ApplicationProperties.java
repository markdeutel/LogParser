package de.fau.fuzzing.logparser;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.Properties;

public class ApplicationProperties
{
    private static final String PROPERTIES_PATH = Paths.get(ApplicationProperties.class.getProtectionDomain()
            .getCodeSource().getLocation().getPath()).getParent().resolve("application.properties").toString();

    private static ApplicationProperties instance = null;

    private final Properties properties;
    private final String databaseUrl;
    private final String databaseUserName;

    private ApplicationProperties()
    {
       try
       {
           properties = new Properties();
           properties.load(new FileInputStream(new File(PROPERTIES_PATH)));
           databaseUrl = properties.getProperty("database.url");
           databaseUserName = properties.getProperty("database.user");
       }
       catch (IOException ex)
       {
           throw new RuntimeException(ex);
       }
    }

    public static ApplicationProperties getInstance()
    {
        if (instance == null)
            instance = new ApplicationProperties();
        return instance;
    }

    public void setDatabaseUrl(final String databaseUrl)
    {
        storeProperty("database.url", databaseUrl);
    }

    public String getDatabaseUrl()
    {
        return databaseUrl;
    }

    public void setDatabaseUserName(final String databaseUserName)
    {
        storeProperty("database.user", databaseUserName);
    }

    public String getDatabaseUserName()
    {
        return databaseUserName;
    }

    private void storeProperty(final String key, final String value)
    {
        try(final FileOutputStream stream = new FileOutputStream(new File(PROPERTIES_PATH)))
        {
            properties.setProperty(key, value);
            properties.store(stream, null);
        }
        catch (IOException ex)
        {
            throw new RuntimeException(ex);
        }
    }
}
