package de.fau.fuzzing.logparser;

import com.google.common.collect.SetMultimap;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import de.fau.fuzzing.logparser.database.MySQLAccess;
import de.fau.fuzzing.logparser.latex.LatexTemplateWriter;
import de.fau.fuzzing.logparser.parser.AppLogFileParser;
import de.fau.fuzzing.logparser.parser.ApplicationLog;
import de.fau.fuzzing.logparser.parser.JsonSetMultimapSerializer;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class LogParser
{
    public static void main(String[] args) throws Exception
    {
        if (args.length < 2)
            return;

        Path sourcePath = Paths.get(args[0]);
        try (DirectoryStream<Path> directoryStream = Files.newDirectoryStream(sourcePath))
        {
            try(MySQLAccess databaseAccess = new MySQLAccess())
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
                        clearOutputLine(outputLine);
                        outputLine = String.format("Parsing logfile: %s\r", filePath.toString());
                        System.out.print(outputLine);

                        Path outputPath = Paths.get(args[1]).resolve(filePath.getFileName().toString().replaceAll(".app.log", ".json"));
                        ApplicationLog applicationLog = AppLogFileParser.parseLogFile(filePath);//FileParser.parseLogFile(filePath);
                        appLogs.add(applicationLog);

                        // write result to file
                        writeResult(outputPath, applicationLog);

                        // write result to database
                        databaseAccess.insertApplicationLog(applicationLog);
                    }
                }
                clearOutputLine(outputLine);

                // write result latex file
                Collections.sort(appLogs, (o1, o2) -> o2.getCrashes().keySet().size() - o1.getCrashes().keySet().size());
                Path latexPath = Paths.get(args[1]).resolve("testresults.tex");
                LatexTemplateWriter.writeLatexTemplate(latexPath, appLogs);
            }
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
