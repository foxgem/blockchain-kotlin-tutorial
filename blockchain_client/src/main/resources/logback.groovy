import ch.qos.logback.classic.Level
import ch.qos.logback.classic.encoder.PatternLayoutEncoder

appender("Console", ConsoleAppender) {
    encoder(PatternLayoutEncoder) {
        pattern = "%d [%thread] %-5level %logger{36} - %msg%n"
    }
}

appender("R", RollingFileAppender) {
    file = "clock.log"
    encoder(PatternLayoutEncoder) {
        pattern = "%d [%thread] %-5level %logger{36} - %msg%n"
    }
    rollingPolicy(FixedWindowRollingPolicy) {
        fileNamePattern = "clock.log.%i"
        minIndex = 1
        maxIndex = 10
    }
    triggeringPolicy(SizeBasedTriggeringPolicy) {
        maxFileSize = "10MB"
    }
}

logger("io.vertx", Level.WARN)
logger("io.netty", Level.WARN)
logger("ch.qos.logback", Level.WARN)
logger("com.zaxxer", Level.WARN)
logger("org.quartz", Level.WARN)
logger("io.vertx", Level.WARN)

final String CLOCK_LOG_LEVEL = System.getProperty("CLOCK_LOG_LEVEL") ?:
        System.getenv("CLOCK_LOG_LEVEL")

root(Level.valueOf(CLOCK_LOG_LEVEL), ["Console", "R"])
