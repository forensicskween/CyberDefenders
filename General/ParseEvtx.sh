#/bin/bash

#Filter out the empty event logs
find 'winevt/Logs' -name "*.evtx" -size +69k -print0 | while read -d $'\0' file
do
    evtxtract "${file}" > "${file}.txt" 2>/dev/null 
    mv "${file}.txt" output/
done
