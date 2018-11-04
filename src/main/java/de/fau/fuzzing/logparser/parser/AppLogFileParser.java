package de.fau.fuzzing.logparser.parser;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Scanner;

public class AppLogFileParser
{
    private static final String EXCEPTION_START_PATTERN = ".*Exception.*";
    private static final String EXCEPTION_PATTERN = "(at .*|Caused by: .*)";

    public static ApplicationLog parseLogFile(final Path filePath) throws IOException
    {
        try (final BufferedReader reader = Files.newBufferedReader(filePath, StandardCharsets.ISO_8859_1))
        {
            String line, currIntent = null;
            LogEntry lastEntry = null;
            LogException currException = null, currCrashException = null;
            final ApplicationLog log = new ApplicationLog();
            while ((line = reader.readLine()) != null)
            {
                final LogEntry entry = new LogEntry(line);
                if (entry.isValid())
                {
                    switch (entry.getTag())
                    {
                        case "IntentFuzzer":
                            String result = handleIntentFuzzerEntry(entry, log);
                            if (result != null)
                                currIntent = result;
                            break;
                            /*
                        case "IntentBuilder":
                            if (entry.getLevel() == LogEntry.INFO)
                                currIntent = entry.getMessage();
                            break;
                            */
                        case "AndroidRuntime":
                            currCrashException = handleRuntimeException(entry, lastEntry, currIntent, currCrashException, log);
                            break;
                        default:
                            // exceptions logged by classes contain the type of the exception in the firs stacktrace line
                            // all other lines start with at or caused by
                            if (entry.getMessage().matches(EXCEPTION_START_PATTERN))
                                currException = handleException(true, entry, currIntent, currException, log);
                            else if (entry.getMessage().matches(EXCEPTION_PATTERN))
                                currException = handleException(false, entry, currIntent, currException, log);

                            break;
                    }
                }
                lastEntry = entry;
            }

            addCrashException(currCrashException, log);
            addException(currException, log);
            return log;
        }
    }

    private static String handleIntentFuzzerEntry(final LogEntry entry, final ApplicationLog log)
    {
        String intent = null;
        String message = entry.getMessage();
        String[] tokens = message.split(":");
        if (tokens.length == 2)
        {
            switch (tokens[0])
            {
                case "Packagename":
                    log.setPackageName(tokens[1].trim());
                    break;
                case "Number of iterations":
                    log.setIterations(Integer.parseInt(tokens[1].trim()));
                    break;
                case "Exported receivers":
                    log.setReceivers(Integer.parseInt(tokens[1].trim()));
                    break;
                case "Exported activities":
                    log.setActivities(Integer.parseInt(tokens[1].trim()));
                    break;
                case "Exported services":
                    log.setServices(Integer.parseInt(tokens[1].trim()));
                    break;
            }
        }
        else
        {
            intent = message;
        }
        return intent;
    }

    private static LogException handleRuntimeException(final LogEntry entry, final LogEntry lastEntry, final String intent,
                                               LogException currException, final ApplicationLog log)
    {
        // A new crash stacktrace starts
        if (entry.getLevel() == LogEntry.ERROR && lastEntry.getLevel() != LogEntry.ERROR)
        {
            addCrashException(currException, log);
            currException = new LogException();
            currException.setCause(intent);
            currException.setComponent(getComponentName(intent));
            currException.setCrash(true);
        }

        if (currException != null)
            currException.addStacktraceLine(entry.getMessage());
        return currException;
    }

    private static LogException handleException(boolean start, final LogEntry entry, final String intent,
                                                       LogException currException, final ApplicationLog log)
    {
        // A new crash stacktrace starts
        if (start)
        {
            addException(currException, log);
            currException = new LogException();
            currException.setCause(intent);
            currException.setComponent(getComponentName(intent));
            currException.setCrash(true);
        }

        if (currException != null)
            currException.addStacktraceLine(entry.getMessage());
        return currException;
    }

    private static void addCrashException(final LogException exception, final ApplicationLog log)
    {
        if (exception != null)
        {
            setExceptionTypeAndMessage(exception);
            log.putCrash(exception.getComponent(), exception);
        }
    }

    private static void addException(final LogException exception, final ApplicationLog log)
    {
        if (exception != null)
        {
            setExceptionTypeAndMessage(exception);
            log.putException(exception.getComponent(), exception);
        }
    }

    private static String getComponentName(String intent)
    {
        if (intent == null)
            return null;

        String component = intent.substring(intent.indexOf("component=") + 10);
        component = component.substring(0, component.indexOf(';'));
        if (component.charAt(component.indexOf('/') + 1) == '.')
            return component.replaceAll("/", "");
        else return component.substring(component.indexOf('/') + 1);
    }

    private static void setExceptionTypeAndMessage(final LogException exception)
    {
        for (final String line : exception.getStacktrace())
        {
            if (!line.startsWith("at") && !line.startsWith("Caused by"))
            {
                final Scanner lineScanner = new Scanner(line);
                while(lineScanner.hasNext())
                {
                    String token = lineScanner.next();
                    if (token.contains("Exception"))
                    {
                        exception.setType(token.replace(":", ""));
                        exception.setMessage(line.substring(line.indexOf(token) + token.length()));
                    }
                }
            }
        }
    }

    /*
    public static void main(String[] args) throws IOException
    {
        ApplicationLog log = AppLogFileParser.parseLogFile(Paths.get(args[0]));
        System.out.println("Done");
    }
    */
}
