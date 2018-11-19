package de.fau.fuzzing.logparser.database;

import de.fau.fuzzing.logparser.ApplicationProperties;
import de.fau.fuzzing.logparser.parser.ApplicationLog;
import de.fau.fuzzing.logparser.parser.LogException;

import java.io.Closeable;
import java.sql.*;

public class MySQLAccess implements Closeable
{
    private static final String DB_PWD = "JavaUnit5";

    private Connection connection = null;

    public MySQLAccess(final String databasePwd) throws ClassNotFoundException, SQLException
    {
        if (databasePwd != null)
        {
            Class.forName("com.mysql.cj.jdbc.Driver");
            final ApplicationProperties properties = ApplicationProperties.getInstance();
            connection = DriverManager.getConnection(properties.getDatabaseUrl(), properties.getDatabaseUserName(), databasePwd);
        }
    }

    public void createTables() throws SQLException
    {
        if (connection != null)
        {
            // drop tables
            final String sqlDropExceptionsQuery = "DROP TABLE IF EXISTS Exceptions";
            final String sqlDropApplicationsQuery = "DROP TABLE IF EXISTS Applications";
            try (final Statement statement = connection.createStatement())
            {
                statement.addBatch(sqlDropExceptionsQuery);
                statement.addBatch(sqlDropApplicationsQuery);
                statement.executeBatch();
            }

            // create tables
            final String sqlCreateApplicationsQuery = "CREATE TABLE Applications (package VARCHAR(255) NOT NULL, activities INTEGER, services INTEGER, " +
                    "receivers INTEGER, PRIMARY KEY ( package ))";
            final String sqlCreateExceptionsQuery = "CREATE TABLE Exceptions (package VARCHAR(255) NOT NULL, component VARCHAR(255) not NULL, number INTEGER NOT NULL, " +
                    "type ENUM('CRASH', 'EXCEPTION'), exceptionType VARCHAR(255), exceptionMessage VARCHAR(4000), cause VARCHAR(8000), PRIMARY KEY ( number, package ), FOREIGN KEY ( package ) REFERENCES Applications( package ))";
            try (final Statement statement = connection.createStatement())
            {
                statement.addBatch(sqlCreateApplicationsQuery);
                statement.addBatch(sqlCreateExceptionsQuery);
                statement.executeBatch();
            }
        }
    }

    public void insertApplicationLog(final ApplicationLog log) throws SQLException
    {
        if (connection != null)
        {
            // insert application data
            insertApplication(log);

            // insert all crashes detected in this application
            int number = 0;
            for (final String key : log.getCrashes().keySet())
            {
                for (final LogException exception : log.getCrashes().get(key))
                {
                    insertLogcatException(number, "CRASH", log.getPackageName(), exception);
                    number++;
                }
            }

            for (final String key : log.getCrashes().keySet())
            {
                for (final LogException exception : log.getExceptions().get(key))
                {
                    insertLogcatException(number, "EXCEPTION", log.getPackageName(), exception);
                    number++;
                }
            }
        }
    }

    private void insertLogcatException(int number, final String type, final String packageName, final LogException exception) throws SQLException
    {
        if (connection != null)
        {
            final String sqlQuery = "INSERT INTO Exceptions (package, component, number, type, exceptionType, exceptionMessage, cause) VALUES (?, ?, ?, ?, ?, ?, ?)";
            try (final PreparedStatement statement = connection.prepareStatement(sqlQuery))
            {
                statement.setString(1, packageName);
                statement.setString(2, exception.getComponent());
                statement.setInt(3, number);
                statement.setString(4, type);
                statement.setString(5, exception.getType());
                statement.setString(6, exception.getMessage());
                statement.setString(7, exception.getCause());
                statement.execute();
            }
        }
    }

    private void insertApplication(final ApplicationLog log) throws SQLException
    {
        if (connection != null)
        {
            final String sqlQuery = "INSERT INTO Applications (package, activities, services, receivers) VALUES (?, ?, ?, ?)";
            try (final PreparedStatement statement = connection.prepareStatement(sqlQuery))
            {
                statement.setString(1, log.getPackageName());
                statement.setInt(2, log.getActivities());
                statement.setInt(3, log.getServices());
                statement.setInt(4, log.getReceivers());
                statement.execute();
            }
        }
    }

    @Override
    public void close()
    {
        try
        {
            if (connection != null)
                connection.close();
        }
        catch (SQLException ex)
        {
            System.err.println(String.format("Failed closing database connection: %s", ex.getMessage()));
        }
    }
}
