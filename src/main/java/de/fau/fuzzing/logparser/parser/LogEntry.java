package de.fau.fuzzing.logparser.parser;

public class LogEntry
{
    public static final char ASSERT = 'A';
    public static final char DEBUG = 'D';
    public static final char ERROR = 'E';
    public static final char INFO = 'I';
    public static final char VERBOSE = 'V';
    public static final char WARN = 'W';

    private char level;
    private String tag, message;
    private boolean valid = true;

    public LogEntry(final String line)
    {
        String[] tokens = line.split("\\s+");
        if (tokens.length < 6)
        {
            valid = false;
            return;
        }

        try
        {
            level = tokens[4].charAt(0);
            tag = tokens[5].replace(":", "");
            message = line.substring(line.lastIndexOf(tag) + tag.length() + 2).trim();
        }
        catch (Exception e)
        {
            valid = false;
        }
    }

    public boolean isValid()
    {
        return valid;
    }

    public char getLevel()
    {
        return level;
    }

    public String getTag()
    {
        return tag;
    }

    public String getMessage()
    {
        return message;
    }
}
