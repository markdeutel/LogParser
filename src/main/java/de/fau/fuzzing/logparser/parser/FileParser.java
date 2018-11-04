package de.fau.fuzzing.logparser.parser;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Scanner;

public class FileParser
{
    private static final String INTENT_FUZZER_PATTER = ".* I IntentFuzzer: .*";
    private static final String CRASH_PATTER = ".* E AndroidRuntime: .*";
    private static final String EXCEPTION_PATTERN = ".* W .*: (.*Exception.*|.*at .*)";

    public static ApplicationLog parseLogFile(Path filePath) throws IOException
    {
        try (BufferedReader reader = Files.newBufferedReader(filePath, StandardCharsets.ISO_8859_1))
        {
            String line, lastLine = "", intent = "";
            LogException crashException = null;
            LogException logcatException = null;
            ApplicationLog applicationLog = new ApplicationLog();
            while ((line = reader.readLine()) != null)
            {
                line = line.trim();
                if (line.matches(CRASH_PATTER))
                {
                    if (!lastLine.matches(CRASH_PATTER) || line.contains("FATAL EXCEPTION: main"))
                    {
                        if (crashException != null)
                        {
                            setExceptionTypeAndMessage(crashException);
                            applicationLog.putCrash(crashException.getComponent(), crashException);
                        }
                        crashException = new LogException();
                        crashException.setCause(intent);
                        crashException.setComponent(getComponentName(intent));
                    }

                    String startStr = "E AndroidRuntime:";
                    crashException.addStacktraceLine(line.substring(line.indexOf(startStr) + startStr.length() + 1).trim());
                }
                else if (line.matches(INTENT_FUZZER_PATTER))
                {
                    String message = "I IntentFuzzer:";
                    message = line.substring(line.indexOf(message) + message.length() + 1);
                    if (message.startsWith("Packagename:"))
                        applicationLog.setPackageName(message.substring(message.indexOf(':') + 2));
                    else if (message.startsWith("Number of iterations:"))
                        applicationLog.setIterations(Integer.parseInt(message.substring(message.indexOf(':') + 2)));
                    else if (message.startsWith("Exported receivers:"))
                        applicationLog.setReceivers(Integer.parseInt(message.substring(message.indexOf(':') + 2)));
                    else if (message.startsWith("Exported activities:"))
                        applicationLog.setActivities(Integer.parseInt(message.substring(message.indexOf(':') + 2)));
                    else if (message.startsWith("Exported services:"))
                        applicationLog.setServices(Integer.parseInt(message.substring(message.indexOf(':') + 2)));
                    else
                        intent = message;
                }
                else if (line.matches(EXCEPTION_PATTERN))
                {
                    if (!lastLine.matches(EXCEPTION_PATTERN))
                    {
                        if (logcatException != null)
                        {
                            setExceptionTypeAndMessage(logcatException);
                            applicationLog.putException(logcatException.getComponent(), logcatException);
                        }
                        logcatException = new LogException();
                        logcatException.setCause(intent);
                        logcatException.setComponent(getComponentName(intent));
                    }

                    String message = line.substring(line.indexOf(" W ") + 3);
                    message = message.substring(message.indexOf(':') + 1).trim();
                    logcatException.addStacktraceLine(message);
                }

                lastLine = line;
            }

            if (crashException != null)
                applicationLog.putCrash(crashException.getComponent(), crashException);
            return applicationLog;
        }
    }

    private static String getComponentName(String intent)
    {
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
}
