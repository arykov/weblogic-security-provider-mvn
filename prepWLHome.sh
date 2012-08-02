#!/bin/bash
if [ ! -d $1/modules ] || [ ! -f $1/wlserver_10.3/server/lib/weblogic.jar ]
then
  echo "Usage: $0 <BEA_HOME>"
  exit 1
fi


REAL_WL_HOME=$1/wlserver_10.3/server/
mkdir -p ./src/main/lib/mbeantypes
mkdir -p ./src/main/lib/schema 
cp ${REAL_WL_HOME}/lib/mbeantypes/wlManagementImplSource.jar ./src/main/lib/mbeantypes/
cp ${REAL_WL_HOME}/lib/mbeantypes/wlManagementMBean.jar ./src/main/lib/mbeantypes/
cp ${REAL_WL_HOME}/lib/schema/weblogic-domain-binding.jar ./src/main/lib/schema/
