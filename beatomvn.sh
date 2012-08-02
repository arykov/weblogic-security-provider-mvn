#!/bin/bash
if [ ! -d $1/modules ] || [ ! -f $1/wlserver_10.3/server/lib/weblogic.jar ]
then
  echo "Usage: $0 <BEA_HOME>"
  exit 1
fi

unixname=`uname -o`
weblogic_jar=$1/wlserver_10.3/server/lib/weblogic.jar
if [ "$unixname" = "Cygwin" ]
  then
    weblogic_jar="$(cygpath -w $weblogic_jar)"
  fi
mvn install:install-file -DgroupId=weblogic -DartifactId=weblogic -Dversion=10.3 -Dpackaging=jar -Dfile=$weblogic_jar
for f in $1/modules/*.jar; 
do 
  echo "Processing $f file.."; 
  f1=`echo \`basename $f\`|sed 's/\.jar//'|sed 's/_/ /'`
  arr=($f1)
  echo Artifact ID: ${arr[0]}
  echo Version: ${arr[1]}
  if [ "$unixname" = "Cygwin" ]
  then
    f="$(cygpath -w $f)"
  fi
  mvn install:install-file -DgroupId=weblogic -DartifactId=${arr[0]} -Dversion=${arr[1]} -Dpackaging=jar -Dfile=$f

done
