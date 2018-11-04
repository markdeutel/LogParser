package de.fau.fuzzing.logparser.latex;

import de.fau.fuzzing.logparser.parser.ApplicationLog;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class LatexTemplateWriter
{

    public static void writeLatexTemplate(Path outputPath, List<ApplicationLog> logs) throws IOException
    {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                ClassLoader.getSystemClassLoader().getResourceAsStream("rendered.tex"))))
        {
            try (BufferedWriter writer = Files.newBufferedWriter(outputPath, StandardCharsets.ISO_8859_1))
            {
                String line;
                while ((line = reader.readLine()) != null)
                {
                    if (line.equals("%s"))
                    {
                        int count = 1;
                        StringBuilder sb = new StringBuilder();
                        for (ApplicationLog appLog : logs)
                        {
                            sb.append(asLatexString(appLog.getPackageName())).append(" & ");
                            sb.append(appLog.getActivities()).append("/");
                            sb.append(appLog.getServices()).append("/");
                            sb.append(appLog.getReceivers()).append(" & ");
                            sb.append(appLog.getCrashes().keySet().size()).append(" & ");
                            sb.append(appLog.getCrashes().values().size()).append(" & ");
                            sb.append(appLog.getExceptions().values().size()).append(" \\\\");
                            if (count % 10 == 0 && count != logs.size())
                                sb.append("\\hline");

                            sb.append(System.lineSeparator());
                            count++;
                        }
                        writer.write(sb.toString() + System.lineSeparator());
                    }
                    else if (line.contains("%d"))
                    {
                        writer.write(asLatexString(String.format(line, logs.size(), logs.get(0).getIterations())));
                    }
                    else
                    {
                        writer.write(line + System.lineSeparator());
                    }
                }
            }
        }
    }

    private static String asLatexString(String str)
    {
        return str.replace("\\", "\\textbackslash ").replace("&", "\\&").replace("%", "\\%")
                .replace("$", "\\$").replace("#", "\\#")
                .replace("_", "\\_").replace("{", "\\{")
                .replace("}", "\\}").replace("^", "\\textasciicircum ")
                .replace("~", "\\textasciitilde ");
    }
}
