# About
`LogParser` is a command line tool, which can be used to parse logs generated by Android's logcat service during the execution of the `IntentFuzzer` module. All generated logs have to be formatted in logcat's standard output format for this tool to work properly. The tool searches the log entries, stored in the files, for all kinds of stacktraces. Based on the found data it generates output files containing the stacktraces ordered by the components in which they were raised.

# Build
Build by using gradle wrapper locally:  
```console
$ cd ~/path/to/LogParser  
$ ./gradlew build  
$ ./gradlew fatJar # build standalone jar  
```

# Options and Configuration
The `LogParser` tool offers a range of command line options
 - *-h*: print the help dialog
 - *-f*: specify a folder containing logcat output stored in files having the file extension `.app.log`
 - *-o*: specify a folder for generated result files
 - *-d*: specify whether the generated output shall be stored in a specified mySQL database
 - *-p*: specify a new database url (path). The url will be used until a new one is defined.
 - *-u*: specify a new database account which shall be used to store the data. The account will be used until a new one is defined
