#!/bin/sh
APP_BASE_NAME=`basename "$0"`
APP_HOME=`pwd -P`
CLASSPATH="$APP_HOME/gradle/wrapper/gradle-wrapper.jar"
exec "$JAVA_HOME/bin/java" -classpath "$CLASSPATH" org.gradle.wrapper.GradleWrapperMain "$@"
