#!/bin/sh

copy() {
    dir=`dirname $2`
    dname=${dir##*/}
    if [[ ! -d $1/$dname ]]; then
        mkdir -p $1/$dname
        cp $dir/*.patch $1/$dname
    fi
    cp $2 $1/$dname
    echo "cp $2 to $1/$dname"
}

for dir in `ls ../linux/`; do
    if [[ `ls ../linux/$dir/ | wc -l` -le 1 ]]; then
        continue
    fi
    for ql in `ls ../linux/$dir/*.ql`; do
        #des=`sed -n '4p' $ql`
        root=`sed -n '4p' $ql | cut -d '-' -f 3 | cut -d '/' -f 1`
        sec=`sed -n '4p' $ql | cut -d '-' -f 3 | cut -d '/' -f 2`
        #echo $root
        flag=0
        for token in fs kernel mm net; do
            if [ "$root" == "$token" ]; then
                copy $token $ql
                flag=1
                break
            fi
        done
        if [[ $flag -eq 1 ]]; then
            continue
        fi
        if [[ "$root" == "security" || "root" == "crypto" ]]; then
            copy "./security-crypto" $ql
            continue
        fi
        if [[ "$root" == "arch" && "$sec" == "x86" ]]; then
            copy "./arch-x86" $ql
            continue
        fi
        if [[ "$root" == "drivers" ]]; then
            flag=0
            for token in "net" "gpu" "staging" "media" "scsi"; do
                if [[ "$sec" == "$token" ]]; then
                    copy "drivers/$token" $ql
                    flag=1
                    break
                fi
            done
            if [[ $flag -eq 0 ]]; then
                copy "drivers/misc" $ql
            fi
            continue
        fi
        copy "./misc" $ql
    done
done
