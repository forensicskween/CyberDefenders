#/bin/bash
for f in 'Registry Hives'/*; do 
    regfexport "$f" > "${f}.txt"
done

find 'Users Registry Hives' -name "*.DAT" -print0 | while read -d $'\0' file
do
    regfexport "${file}" > "${file}.txt"
done
