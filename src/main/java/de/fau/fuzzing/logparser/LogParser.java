package de.fau.fuzzing.logparser;

import com.google.common.collect.SetMultimap;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import de.fau.fuzzing.logparser.database.MySQLAccess;
import de.fau.fuzzing.logparser.latex.LatexTemplateWriter;
import de.fau.fuzzing.logparser.parser.AppLogFileParser;
import de.fau.fuzzing.logparser.parser.ApplicationLog;
import de.fau.fuzzing.logparser.parser.JsonSetMultimapSerializer;
import org.apache.commons.cli.*;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class LogParser
{
    public static void main(String[] args) throws ParseException
    {
        final Options options = new Options();
        options.addOption("h", false, "print this dialog");
        options.addOption("f", true, "specify the input folder");
        options.addOption("o", true, "specify the output folder");
        options.addOption("d", false, "write output into mySQL database");

        final CommandLineParser parser = new DefaultParser();
        final CommandLine cmd = parser.parse(options, args);

        if (cmd.hasOption("h") || args.length == 0)
        {
            final HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp("LogParser", options);
            return;
        }

        Path sourcePath = Paths.get(".");
        Path outputPath = Paths.get(".");
        if (cmd.hasOption("f"))
            sourcePath = Paths.get(cmd.getOptionValue("f"));
        if (cmd.hasOption("o"))
            outputPath = Paths.get(cmd.getOptionValue("o"));

        try (DirectoryStream<Path> directoryStream = Files.newDirectoryStream(sourcePath))
        {
            try(MySQLAccess databaseAccess = new MySQLAccess(cmd.hasOption("d")))
            {
                // prepare database
                databaseAccess.createTables();

                // parse log files
                String outputLine = "";
                List<ApplicationLog> appLogs = new ArrayList<>();
                for (Path filePath : directoryStream)
                {
                    PathMatcher fileMatcher = FileSystems.getDefault().getPathMatcher("glob:**.app.log");
                    if (fileMatcher.matches(filePath))
                    {
                        System.out.println(String.format("Parsing logfile: %s", filePath.toString()));
                        Path outputFilePath = outputPath.resolve(filePath.getFileName().toString().replaceAll(".app.log", ".json"));
                        ApplicationLog applicationLog = AppLogFileParser.parseLogFile(filePath);//FileParser.parseLogFile(filePath);
                        appLogs.add(applicationLog);

                        // write result to file
                        writeResult(outputFilePath, applicationLog);

                        // write result to database
                        if (cmd.hasOption("d"))
                            databaseAccess.insertApplicationLog(applicationLog);
                    }
                }
                clearOutputLine(outputLine);

                // write result latex file
                Collections.sort(appLogs, (o1, o2) -> o2.getCrashes().keySet().size() - o1.getCrashes().keySet().size());
                Path latexPath = Paths.get(args[1]).resolve("testresults.tex");
                LatexTemplateWriter.writeLatexTemplate(latexPath, appLogs);
            }
            catch (SQLException | ClassNotFoundException sqlex)
            {
                System.err.println("Failed connecting to mySQL database");
                sqlex.printStackTrace();
            }
        }
        catch (IOException ioex)
        {
            System.err.println(String.format("Failed parsing directory stream: %s", sourcePath.toString()));
            ioex.printStackTrace();
        }
    }

    private static void writeResult(Path outputFile, Object data) throws IOException
    {
        // write output to file
        try (BufferedWriter writer = Files.newBufferedWriter(outputFile, StandardCharsets.ISO_8859_1))
        {
            Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping()
                    .registerTypeAdapter(SetMultimap.class, new JsonSetMultimapSerializer()).create();
            writer.write(gson.toJson(data));
        }
    }

    private static void clearOutputLine(String line)
    {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < line.length(); ++i)
            sb.append(' ');
        System.out.print(sb.toString() + '\r');
    }
}
