#!/bin/bash
#default values
defaultversion=1036
groupid='com.bea.weblogic'${defaultversion}
unixname=`uname -o`
printNameVersion(){
  jar=$1
  #echo "<!--"
  #cat META-INF/MANIFEST.MF 
  #echo "-->"
  bundleName=$(cat META-INF/MANIFEST.MF | grep 'Bundle-SymbolicName:' | sed 's/Bundle-SymbolicName://'|sed 's/ //g')
  bundleVersion=$(cat META-INF/MANIFEST.MF | grep 'Bundle-Version' | sed 's/Bundle-Version://'|sed 's/ //g')  
  if [ "${bundleName}" =  "" ]
    then
      artifactId=`echo \`basename $jar\`|sed 's/\.jar//'`      
    else
      artifactId=${bundleName}      
  fi
  if [ "${bundleVersion}" = "" ]
    then
      version=${defaultversion}
    else
      version=${bundleVersion}      
  fi
  #always default version
  version=${defaultversion}
  
  
  echo '
        <artifactId>'${artifactId}'</artifactId>
        <version>'${version}'</version>'
}

extractManifest(){
   file=${1}
   if [ "$unixname" = "Cygwin" ]
     then
          file="$(cygpath -w ${file})"
     fi  
   
   
   jar xvf ${file} META-INF/MANIFEST.MF > /dev/null
   
}

createPom(){
  jar=$1
  
  echo '<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/maven-v4_0_0.xsd">
      <modelVersion>4.0.0</modelVersion>
      <groupId>'${groupid}'</groupId>
      <packaging>jar</packaging>'
  
  extractManifest ${jar}
  printNameVersion ${jar}
  jardir=`dirname ${jar}`   
  
  echo '<dependencies>'
  dependencies=$(cat META-INF/MANIFEST.MF | sed ':a;N;$!ba;s/\n //g'|grep "Depends-On"|tr ' ' '\n'|grep -v "Depends-On" |grep -v "^$") 
  if [ "${dependencies}" = "" ]
  then
    #CLASSPATH dependencies    
    dependencies=$(cat META-INF/MANIFEST.MF | sed ':a;N;$!ba;s/\n //g'|grep Class-Path|tr ' ' '\n'|grep jar)    
    
    for dependency in ${dependencies}
    do    
      dependencypath=${jardir}'/'${dependency}    
      if [ -a ${dependencypath} ]
        then
          echo '
          <dependency>
            <groupId>'${groupid}'</groupId>'            
            extractManifest ${dependencypath}            
            printNameVersion ${dependencypath}
          echo '
          </dependency>'
    
      fi
    done
  else
    #Depends-On dependencies
    if [ "$jar" != "$jardir/com.oracle.weblogic.rac.ucp_1.1.0.0.jar" ]
    then
      for dependency in $dependencies
      do
        dependencyAndVersion=(${dependency//;version=/ })        
        artifactId=${dependencyAndVersion[0]}
        
        if [  ${#dependencyAndVersion[@]} -eq 1 ]
        then
          version='1.0'
        else
          version=${dependencyAndVersion[1]}
        fi
        #always default version
        version=${defaultversion}
        #invalid dependency. would not want this resolved
        if [[ $artifactId =~ .*=.* ]]
        then
          echo "
             <!--skipping ${artifactId}:${version}-->"
        else
          echo '
            <dependency>
              <groupId>'${groupid}'</groupId>            
              <artifactId>'${artifactId}'</artifactId>
              <version>'${version}'</version>          
            </dependency>'
          fi
            
      
        
      done
    fi
    
  fi
  echo '</dependencies></project>'
}

loadJar() {
  f=${1}
  pomFile='/tmp/pom.xml'
  createPom "${f}" > ${pomFile}

  if [ "$unixname" = "Cygwin" ]
  then
        f="$(cygpath -w ${f})"
        pomFile="$(cygpath -w ${pomFile})"
  fi
  
  mvn install:install-file -Dfile="${f}" -DpomFile=${pomFile}  

}
#check BEA_HOME that was passed if it was passed
if [ ! -d $1/modules ] || [ ! -f $1/wlserver_10.3/server/lib/weblogic.jar ]
then
  echo "Usage: $0 <BEA_HOME>"
    exit 1
fi


#load all the jars you can find
for f in $(find ${1}/modules/. -name "*.jar")
do
  loadJar ${f}
done

for f in $(find ${1}/wlserver_10.3/. -name "*.jar")
do
  loadJar ${f}
done
