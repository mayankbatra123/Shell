#!/bin/bash

export TERM=xterm

UseR=`id -nu`
source ~/.bash_profile
PATH=/usr/sbin:/sbin:${PATH}

#-- Base Path where script is deployed
BasE_PATH=<>

#-- Logging Path
LogpatH=$BasE_PATH/stat.log


#-- Output Folder
OutpuT_PATH=$BasE_PATH/Output

#-- DisplaY=1 will Hide Output on screen
DisplaY=0

#-- Mailing Variables
MAIL_TO_ADDRESS="<>"
MAIL_CC_ADDRESS="<>"
MAIL_STATUS=$BasE_PATH/stat.report

#-- Min and Max Parameter to the script
MinparaM=1
MaxparaM=3

UploaD=0

#-- Temp file
TMP_DIRPATH=$BasE_PATH/tmp

TmpfilE=$TMP_DIRPATH/stat.tmp
TmpfilE_DISKIO=$TMP_DIRPATH/PERF_DiskiO.tmp
TmpfilE_SNAPSHOT=$TMP_DIRPATH/SnapshoT.tmp
TmpfilE_SAR=$TMP_DIRPATH/SaR.tmp
TmpfilE_OPENSSL=$TMP_DIRPATH/OssL.tmp
TmpfilE_SARBIN=$TMP_DIRPATH/sabinary.tmp
TmpfilE_ALLRPM=$TMP_DIRPATH/allrpm.tmp
TmpfilE_NETSTAT=$TMP_DIRPATH/netstat.lst
TmpfilE_RUNNINGPROCESS=$TMP_DIRPATH/runningprocess.lst
PERF_IOSTAT_OUT=$TMP_DIRPATH/IostatS.tmp

#################################################
# stat Data Variables - [ START ]        #
#################################################
ServeriP=`ifconfig | awk '/inet addr/{print substr($2,6)}' | grep -v "127.0.0.1"`
ServerhosT=`hostname`

#-- stat Datatype Variables
PERF_MEMORY_OUT=$OutpuT_PATH/perf_MemorydetaiL.csv
PERF_SWAP_OUT=$OutpuT_PATH/perf_SwapdetaiL.csv
PERF_CPU_OUT=$OutpuT_PATH/perf_CpudetaiL.csv
PERF_IO_OUT=$OutpuT_PATH/perf_IodetaiL.csv
PERF_LOAD_OUT=$OutpuT_PATH/perf_LoaD.csv
PERF_CACHE_OUT=$OutpuT_PATH/perf_CachE.csv
PERF_DU_OUT=$OutpuT_PATH/perf_DiskusagE.csv
PERF_FD_OUT=$OutpuT_PATH/perf_FiledescriptoR.csv
PERF_JSTAT_OUT=$OutpuT_PATH/perf_JstaT.csv
PERF_LSOF_ALL_OUT=$OutpuT_PATH/perf_LsofalL.csv
PERF_LSOF_USER_PREFIX=$OutpuT_PATH/perf_LsofuseR.csv
PERF_INODE_OUT=$OutpuT_PATH/perf_INode.csv
PERF_PORT_PREFIX=$OutpuT_PATH/perf_PORT
PORT_FILE=$BasE_PATH/PORT_FILE
PERF_URLCHECK_PREFIX=$OutpuT_PATH/URL_FILE
PERF_SNAPSHOT=$OutpuT_PATH/perf_SNAPSHOT.csv

#-- serverstat Datatype Variables
SS_PUPPET_SOURCE=/var/lib/puppet/state/last_run_report.yaml
SS_INTERNET_SOURCE="http://google.com"
SS_PUPPET_OUT=$OutpuT_PATH/ss_PuppetclasseS.csv
SS_SERVERSTAT_OUT=$OutpuT_PATH/ss_ServerstatS.csv
SS_LOGIN_OUT=$OutpuT_PATH/ss_UserlogiN.csv
SS_USERID=scm_admin
SS_PUPPET_STATUS=No

#-- sar Datatype Variables
SardaY=today
SAR_DIR_SOURCE=/var/log/sa
SAR_CPU_OUT=$OutpuT_PATH/sar_CpudetaiL.csv
SAR_LOAD_OUT=$OutpuT_PATH/sar_LoaD.csv
SAR_NW_PREFIX=$OutpuT_PATH/sar_NetworK

#-- software Datatype variables
SW_PACKAGE_SOURCE=$BasE_PATH/checksoftware.lst
SW_PROCESS_OUT=$OutpuT_PATH/sw_ProcesS.csv
SW_VERSION_OUT=$OutpuT_PATH/sw_VersioN.csv

SERVICE_NTPD=/etc/init.d/ntpd
SERVICE_AntiviruS=/etc/init.d/symcfgd


#-- Minutes for which we need to calculate average
RecordseC=1

#################################################
# stat Data Variables - [ END ]          #
#################################################


#################################
# Usage Display for Script      #
#################################
UsagE()
{
        echo
        echo "[ UsagE ] :: sh $0 --datatype=<stat/serverstat/sar/serversoft> [ --upload=<0/1> --sarday=<today/DD>]"
        echo "---------------------------------------------------------"
        echo " | datatype(stat): Generate stat data"
        echo " | datatype(serverstat) : Generate server statistics"
        echo " | datatype(sar) : Capture SAR output"
        echo " | datatype(serversoft) : Capture Software list"
        echo " |--------------------------------------------------------"
        echo " | upload(0) : Upload generated data into database"
        echo " | upload(1) : Do not Upload generated data into database (default)"
        echo "----------------------------------------------------------"
        echo " | sarday(today) : Use this option with --datatype=sar - today is for current day (default)"
        echo " | sarday(DD) : Use this option with --datatype=sar - DD is for current date"
        echo "----------------------------------------------------------"
        ExitprocesS 1
}


#################################################
# Checking Correct Parameters in commandline    #
#################################################
ParamchecK()
{
        ARG=$1
        VAL=$2
        VtemP=`echo $ARG | grep "\-\-$VAL="`
        if [ $? -ne 0 ]
        then
                UsagE
        fi
}

BlankvaL()
{
        VAR=$1
        if [ ! $VAR ]
        then
                UsagE
        fi
}

ExitprocesS()
{
        rm -rf $TmpfilE $TmpfilE_SNAPSHOT $TmpfilE_DISKIO $TmpfilE_SAR $TmpfilE_OPENSSL $TmpfilE_SARBIN
        exit $1
}

ProcesschecK()
{
	LoggeR "Checking if process is already running" 1

        ps -aef | grep "sh /data/admin/scripts/stat/stat.sh --datatype=stat" | grep -v grep > $TmpfilE
        if [ $(cat $TmpfilE | wc -l) -gt 2 ]
	then
                LoggeR "Script already running" 9
		ExitprocesS
	else
                LoggeR " | Good to Continue" 1
        fi
}

#################################################
# Logger function                               #
#################################################
LoggeR()
{
        MessagetypE=$2
        case $MessagetypE in
        0)
                #-- Normal Message
                MessageheadeR=INFO
                ColorschemE=9
                ;;
        1)
                #-- SUCCESS Message
                MessageheadeR=INFO
                ColorschemE=2
                ;;
        2)
                #-- Header Message
                MessageheadeR=INFO
                ColorschemE=1
                ;;
        3)
                #-- WARNING Message
                MessageheadeR=WARN
                ColorschemE=5
                ;;
        4)
                #-- ERROR Message
                MessageheadeR=ERROR
                ColorschemE=4
                ;;
        8)
                #-- USAGE Info
                MessageheadeR=USAGE
                ColorschemE=1
                ;;
        9)
                #-- ABORT Script
                MessageheadeR=ABORT
                ColorschemE=4
                ;;
        *)
                #-- UNKNOWN Message
                MessageheadeR=UNKNOWN
                ColorschemE=4
                ;;
        esac

        tput setf $ColorschemE

        LogdatE=`date +%Y%m%d:%H:%M:%S`
        ScriptnamE=`basename $0 | cut -d"." -f1`
        ScriptpiD=$$

        if [ $DisplaY -eq 1 ]
        then
                echo $LogdatE :: $MessageheadeR :: `hostname`:$ScriptnamE:$ScriptpiD - $1 >> $LogpatH
        else
                echo $LogdatE :: $MessageheadeR :: `hostname`:$ScriptnamE:$ScriptpiD - $1 | tee -a $LogpatH
        fi
        tput sgr0
}

#########################
# Mailing functions     #
#########################
ReportheadeR()
{
        echo "Mime-Version: 1.0" > $MAIL_STATUS
        echo "Content-type: text/html; charset="iso-8859-1"" >> $MAIL_STATUS
        echo "From: Linux Admin Team <scm@nagaro.com" >> $MAIL_STATUS
        echo "To: $MAIL_TO_ADDRESS" >> $MAIL_STATUS
        echo "CC: $MAIL_CC_ADDRESS" >> $MAIL_STATUS
        echo "Subject: "$MsG_TitlE"" >> $MAIL_STATUS

        echo "Hello All," >> $MAIL_STATUS
        echo >> $MAIL_STATUS
        date >> $MAIL_STATUS
        echo "$MsG_TitlE" >> $MAIL_STATUS
        echo >> $MAIL_STATUS

}

ReportfooteR()
{

        echo >> $MAIL_STATUS
        echo "NEXT STEP: Please Contact System Administrator" >> $MAIL_STATUS
        echo >> $MAIL_STATUS
        echo "Regards" >> $MAIL_STATUS
        echo "Support Team" >> $MAIL_STATUS
        echo "" >> $MAIL_STATUS
        echo "" >> $MAIL_STATUS
        echo "Note: This is system generated mail. Please do not reply on this." >> $MAIL_STATUS
}

FailreporT()
{
	HostdetailS_IP=`ifconfig | awk '/inet addr/{print substr($2,6)}' | grep -v "127.0.0.1"`
	HostdetailS_NAME=`hostname`
        LoggeR "Sending Failure Alert" 4

        MsG_TitlE="ALERT | stat Script Execution Failed ($HostdetailS_NAME)"
        ReportheadeR
        echo "$1 - $HostdetailS_IP" >> $MAIL_STATUS
        ReportfooteR

        $echo | mutt -H $MAIL_STATUS
}

#################################
# Error Capturing               #
#################################
ErrorchecK()
{
        ErrorevenT="$1"
        if [ $StatuS -ne 0 ]
        then
                LoggeR "Status on $ErrorevenT - FAILURE" 4
                FailreporT "Status on $ErrorevenT - FAILURE"
                echo
                ExitprocesS 1
        fi
}

CheckdiR()
{
        CheckdirnamE=$1
        if [ ! -d $CheckdirnamE ]
        then
                LoggeR "$CheckdirnamE directory not exists. Creating Dir" 5
                mkdir -p $CheckdirnamE
                StatuS=$?
                ErrorchecK "Create Directory - $CheckdirnamE"
        fi
}

FilechecK()
{
        FiletochecK="$1"
        TypetochecK=$2

        if [ ! -$TypetochecK "$FiletochecK" ]
        then
                StatuS=1
        else
                StatuS=0
        fi
}

SetnumchecK()
{
        NumchecK=`expr $NumchecK + 1`
}

StatuschecK()
{
	case $StatuS in
	126)
		LoggeR "Last Command Status: FAILED - Possibly Permission Issue" 4
		;;
	0)
		LoggeR "Last Command Status: Good" 1
		;;
	1)
		LoggeR "Last Command Status: NOT OK" 4
		;;
	*)
		LoggeR "Last Command Status: Unknown" 4
	esac
}

#################################
# SERVERSTAT Capturing          #
#################################

#-- SERVERSTAT: login details
SS_LogiN()
{
	LoggeR "Server Statistics [ Login Details ]" 1

        last -w|grep -v scm_admin|head -5 > $SS_LOGIN_OUT
	last -w|grep scm_admin|head -5 >> $SS_LOGIN_OUT
}

#-- SERVERSTAT: RAM details
SS_RamdetailS()
{
	LoggeR "Server Statistics [ Memory ]" 1

        TOTAL_RAM=`free -g|grep Mem|awk '{print $2}'`
        USED_RAM=`free -g|grep Mem|awk '{print $3}'`
}


#-- SERVERSTAT: DISK details
SS_TotaldisK()
{
	LoggeR "Server Statistics [ Disk ]" 1

        TotalSpace=`df -h --total  | grep total | awk '{printf $2}'`
        NumericValue=`df -h --total  | grep total | awk '{printf $2}' | tr -dc [0-9]{.}`
        Prefix=`df -h --total  | grep total | awk '{printf $2}' | tr -d [0-9]{.}`
        if [ "$Prefix" == "M" ];
        then
                continue
        elif [ "$Prefix" == "T" ];
        then
                SUM=`expr $NumericValue \* 1024`
        else
                SUM=$NumericValue
        fi
}

#-- SERVERSTAT: CPU details
SS_CpuarcH()
{
        LoggeR "Server Statistics [ CPU Architecture ]" 1

        ARCHITECTURE=`lscpu|grep Architecture|awk '{print $2}'`
        COUNT_OF_CPU=`lscpu|grep "CPU(s)"|head -1|awk '{print $2}'`
}

#-- SERVERSTAT: MACHINE type
SS_RedhatreleasE()
{
        LoggeR "Server Statistics [ RedHat Release ]" 1

        if [ -f /etc/redhat-release ];then
                MACHINE_TYPE=`cat /etc/redhat-release|head -1`

        elif [ -f /etc/issue ]; then
                MACHINE_TYPE=`cat /etc/issue|head -1`
        fi
}

#-- SERVERSTAT: PUPPET Check
SS_PuppeT()
{
    #--checking puppet running or not
    LoggeR "Server Statistics [ Puppet Check ]" 1

    service puppet status
    StatuS=$?
    StatuschecK

    if [ $StatuS -eq 0 ]
    then
        SS_PUPPET_STATUS='Yes'
    else
        SS_PUPPET_STATUS='No'
    fi

	#--Checking when puppet was ran last
	if [ -f $SS_PUPPET_SOURCE ]
	then
    		PUPPET_RUN_STATUS=`ls -l $SS_PUPPET_SOURCE| awk '{print $6, $7}'`
		grep -e "resource: Package\[" -e " time:" -e "title:" -e "changed:" -e "failed:" -e "out_of_sync:" $SS_PUPPET_SOURCE | grep "resource: Package\["  -A5 | grep -v -e "\-\-" -e "resource: Package\[" | awk '{ printf "%s", $0; if (NR % 5 == 0) print ""; else printf " " }' | tr -s " " | sed 's/ time: //g;s/ out_of_sync: /,/g;s/ changed: /,/g;s/ title: /,/g;s/ failed: /,/g' | awk '{print $4,$1,$2,$3,$5}' OFS=',' FS=',' > $SS_PUPPET_OUT
	    fi
}

#-- SERVERSTAT: Antivirus Check
SS_SymantecantiviruS()
{
	LoggeR "Server Statistics [ Symantec AntiviruS Check ]" 1

	if [ -f $SERVICE_AntiviruS ];then
        VAR=`$SERVICE_AntiviruS status`
        if [ "$VAR" == "symcfgd is running" ];then
            SYMANTEC_CHECK=Yes
        else
            SYMANTEC_CHECK=No
        fi
            else
		SYMANTEC_CHECK="No Info"
    fi
}

#-- SERVERSTAT: Processor Information
SS_ProcessoR()
{
    LoggeR "Server Statistics [ CPU Processsor ]" 1

    PROCESSOR=`cat /proc/cpuinfo|grep "cpu MHz"| awk '{print$4,$2}'`
}

#-- SERVERSTAT: Server Uptime
SS_ServeruptimE()
{
	LoggeR "Server Statistics [ Server Uptime ]" 1

	UPTIME_VALUE=`cat /proc/uptime |awk '{print $1}'`
	UPTIME_DAYS=`uptime|awk '{print $3, $4}'|awk -F, '{print $1}'`
	TZONE=`grep ZONE /etc/sysconfig/clock|awk -F'=' '{print $2}'|sed 's/"//g'`
}

#-- SERVERSTAT: Check stat run
SS_statruN()
{	TEMP_VAR=
	stat_Script=No
	CHECK_DATE=`date +%d-%b-%Y --date="1 days ago"`
	TEMP_VAR=`cat $LogpatH|grep "Server stat as on $CHECK_DATE"`
		if [ ! -z "$TEMP_VAR" ]; then
			stat_Script=Yes
		else
			stat_Script=No
		fi

}


#-- SERVERSTAT: Internet Check
SS_InternetconN()
{
	LoggeR "Server Statistics [ Internet Connectivity ]" 1

	wget -q --spider "$SS_INTERNET_SOURCE"
	if [ $? -eq 0 ];then
		INTERNET_CHECK="Yes"
	else
		INTERNET_CHECK="No"
	fi
}

#-- SERVERSTAT: admin User Check
SS_UseriD()
{
	LoggeR "Server Statistics [ User ID ]" 1

    id $SS_USERID > /dev/null 2>&1
	if [ $? -eq 0 ];then
        ID_EXISTS=Yes
    else
        ID_EXISTS=No
    fi
}

#-- SERVERSTAT: Arch Information
SS_OsbiT()
{
	LoggeR "Server Statistics [ OS Bit ]" 1
    OS_BIT=`uname -m`
	if [ "$OS_BIT" == "i686" ];then
        OS_BIT=32-bit
    elif [ "$OS_BIT" == "x86_64" ];then
        OS_BIT=64-bit
    fi
    REMARKS=NONE
}

#-- SERVERSTAT: Ip details check
SS_GatewayiP()
{
	LoggeR "Server Statistics [ Gateway IP ]" 1
	GATEWAY_IP=`route|grep "default"|awk '{print $2}'`
	MAC=`ip addr show|grep link/ether|awk '{print $2}'`
}

#-- SERVERSTAT: NTP check
SS_NTP()
{
	LoggeR "Server Statistics [ NTP Check ]" 1

	$SERVICE_NTPD status | grep running
	StatuS=$?
	StatuschecK

	if [ $StatuS -eq 0 ]
	then
		CHECK_NTP=Yes
	else
        	CHECK_NTP=No
	fi
}

#-- SERVERSTAT: IPTABLES check
SS_IptableS()
{
	LoggeR "Server Statistics [ IP Tables ]" 1
    /bin/service iptables status >/dev/null 2>&1
    if [ $? -eq 0 ];then
           echo "IPTABLES ACTIVE"
              CHECK_IPTABLES=Yes
    else
            echo "IPTABLES NOT ACTIVE"
               CHECK_IPTABLES=No
    fi
}


#-- SERVERSTAT: OPENSSH version check
SS_OpenssL()
{
	LoggeR "Server Statistics [ Open SSL Version ]" 1
    echo "ssh -V" > $TmpfilE_OPENSSL
    chmod 777 $TmpfilE_OPENSSL
    ./$TmpfilE_OPENSSL > aa 2>&1
    OSS_VERSION=`cat aa|awk -F, '{print $1}'`
    rm -rf $TmpfilE_OPENSSL aa
}

#-- SERVERSTAT: Collect One time Server Statistics
PrepareserverstatsouT()
{
	#--Final output to csv file
	echo "TOTAL_RAM,USED_RAM,ARCHITECTURE,CPUs,PUPPET-AGENT,PUPPET-LAST-RUN,OS,SYMANTEC-ANTIVIRUS,PROCESSOR,UPTIME,INTERNET-CHECK,ROOT_DISK, SCM_USER_CHECK, OS_BIT, REMARKS, GATEWAY_IP,MAC_ADDR, TIME_ZONE, NTP_CHECK, OPENSSH_VERSION, HOSTNAME, UPTIME_SEC, stat_RUN, IPTABLES CHECK" > $SS_SERVERSTAT_OUT 2>&1
	echo $TOTAL_RAM,$USED_RAM,$ARCHITECTURE,$COUNT_OF_CPU,$SS_PUPPET_STATUS,$PUPPET_RUN_STATUS,$MACHINE_TYPE,$SYMANTEC_CHECK,$PROCESSOR,$UPTIME_DAYS,$INTERNET_CHECK,$SUM,$ID_EXISTS,$OS_BIT,"$REMARKS",$GATEWAY_IP,$MAC,$TZONE,$CHECK_NTP,$OSS_VERSION,$ServerhosT,$UPTIME_VALUE,$stat_Script,$CHECK_IPTABLES >> $SS_SERVERSTAT_OUT 2>&1
}



#################################
# stat Capturing         #
#################################

SetcurrentdatE()
{
	CurrentdatE=`date +%Y-%m-%d\ %H:%M:%S`
}

#-- stat: Current snapshot
SnapshoT()
{
        echo "($MonitortypE)|$HeaderstylE" >> $PERF_SNAPSHOT
        cat $TmpfilE_SNAPSHOT >> $PERF_SNAPSHOT
        echo >> $PERF_SNAPSHOT

        tput setf 5
        cat $TmpfilE_SNAPSHOT
        tput sgr0
}

#-- stat: Users Details
PERF_UserS()
{
        MonitortypE="User"
        LoggeR "[ $NumchecK ] Processing User details.." 1
        w | grep -v days > $TmpfilE
        StatuS=$?
        ErrorchecK "$MonitortypE Details"
        SetnumchecK
        if [ $DisplaY -eq 0 ]
        then
                LoggeR "User Logged in details [`uptime | cut -d"," -f3 | tr -s " "` ]" 1
                cat $TmpfilE
                echo
        fi
}

PreparenewfilE()
{
        NewfilenamE="$1"
        VtemP=`grep DateTime $NewfilenamE`
        if [ $? -eq 1 ]
        then
                echo "$HeaderstylE" > $NewfilenamE
        fi
}

#-- stat: Memory Details
PERF_MemorY()
{
        MonitortypE="Memory"
        LoggeR "[ $NumchecK ] Processing Memory details.." 1
        HeaderstylE="DateTime,Total,Used,Free,Shared,Buffers,Cached"
        free -m | grep -v "buffers/" | tr -s " " > $TmpfilE

        StatuS=$?
        ErrorchecK "$MonitortypE Details"
        SetnumchecK

        if [ $DisplaY -eq 0 ]
        then
                LoggeR "$MonitortypE details [ `free -m | tr -s " " | grep Mem | cut -d" " -f2`MB ]::" 1
                cat $TmpfilE
                echo
        fi

        if [ ! -f $PERF_MEMORY_OUT ]
        then
                echo "$HeaderstylE" > $PERF_MEMORY_OUT
        else
                PreparenewfilE $PERF_MEMORY_OUT
        fi

        echo -n "$CurrentdatE," >> $PERF_MEMORY_OUT
        echo `grep Mem $TmpfilE | cut -d":" -f2` | sed 's/ /,/g' >> $PERF_MEMORY_OUT
        tail -1 $PERF_MEMORY_OUT > $TmpfilE_SNAPSHOT
        SnapshoT

        #-- Processing Swap Memory Details
        MonitortypE="Swap"
        HeaderstylE="DateTime,Total,Used,Free"
        if [ ! -f $PERF_SWAP_OUT ]
        then
                echo "$HeaderstylE" > $PERF_SWAP_OUT
        else
                PreparenewfilE $PERF_SWAP_OUT
        fi

	echo -n "$CurrentdatE" >> $PERF_SWAP_OUT
        grep Swap $TmpfilE | cut -d":" -f2 | sed 's/ /,/g' >> $PERF_SWAP_OUT
        tail -1 $PERF_SWAP_OUT > $TmpfilE_SNAPSHOT
        SnapshoT
}

#-- stat: Cache Details
PERF_CachE()
{
        LoggeR "[ $NumchecK ] Processing Cache details.." 1
        MonitortypE=Cache
        free -m | tr -s " " > $TmpfilE
        StatuS=$?
        ErrorchecK "$MonitortypE Details"
        SetnumchecK
        HeaderstylE="DateTime,Total,Used,Free"

        if [ $DisplaY -eq 0 ]
        then
                LoggeR "Cache details [ `free -m | tr -s " " | grep "buffers/cache"`MB ]::" 1
                cat $TmpfilE
                echo
        fi
        if [ ! -f $PERF_CACHE_OUT ]
        then
                echo "$HeaderstylE" > $PERF_CACHE_OUT
                echo "$CurrentdatE,"`free -m | tr -s " " | grep Mem | cut -d" " -f2 | sed 's/ /,/g'``grep "buffers/cache" $TmpfilE | cut -d":" -f2 | sed 's/ /,/g'`  >> $PERF_CACHE_OUT
        else
                echo "$CurrentdatE,"`free -m | tr -s " " | grep Mem | cut -d" " -f2 | sed 's/ /,/g'``grep "buffers/cache" $TmpfilE | cut -d":" -f2 | sed 's/ /,/g'`  >> $PERF_CACHE_OUT
        fi
        tail -1 $PERF_CACHE_OUT >> $TmpfilE_SNAPSHOT
        SnapshoT
}


#-- stat: CPU Details
PERF_CpU()
{
        MonitortypE="Cpu"
        LoggeR "[ $NumchecK ] Processing CPU details.." 1
        N=`grep -n "avg-cpu" $PERF_IOSTAT_OUT | tail -1 | cut -d":" -f1`
        M=`echo $N + 1 | bc`
        sed -ne ''$N','$M'p' $PERF_IOSTAT_OUT > $TmpfilE
        HeaderstylE="DateTime,%user,%nice,%sys,%iowait,%steal,%idle"
        SetnumchecK

        if [ $DisplaY -eq 0 ]
        then
                cat $TmpfilE
                echo
        fi
        if [ ! -f $PERF_CPU_OUT ]
        then
                echo "$HeaderstylE" > $PERF_CPU_OUT
        else
                PreparenewfilE $PERF_CPU_OUT
        fi
        echo "$CurrentdatE"`sed -ne ''$N','$M'p' $PERF_IOSTAT_OUT | grep -v user | tr -s " " | sed 's/ /,/g'` >> $PERF_CPU_OUT
        tail -1 $PERF_CPU_OUT > $TmpfilE_SNAPSHOT
        SnapshoT
}

#-- stat: I/O Details
PERF_DiskiO()
{
        MonitortypE="IO"
        LoggeR "[ $NumchecK ] Processing IO details.." 1
        N=`cat $PERF_IOSTAT_OUT | grep -n Device | tail -1 | cut -d":" -f1`
        sed -ne ''$N',$p' $PERF_IOSTAT_OUT > $TmpfilE
        SetnumchecK
        HeaderstylE="Device DateTime:,tps,kB_read/s,kB_wrtn/s,kB_read,kB_wrtn"

        if [ $DisplaY -eq 0 ]
        then
                cat $TmpfilE
                echo
        fi
        if [ ! -f $PERF_IO_OUT ]
        then
                echo "$HeaderstylE" > $PERF_IO_OUT
        else
                PreparenewfilE $PERF_IO_OUT
        fi
        #line=`cat $TmpfilE | grep -v Device | tr -s " " | sed 's/ /,/g'`
	cat $TmpfilE | grep -v Device | tr -s " " | sed 's/ /,/g'|grep -v -e '^$' > $TmpfilE_DISKIO
        cat $TmpfilE_DISKIO >> $PERF_IO_OUT
        cat $PERF_IO_OUT > $TmpfilE_SNAPSHOT
        SnapshoT
	rm -rf $TmpfilE_DISKIO
}

#-- stat: Uptime Details
PERF_SystemloaD()
{
        MonitortypE="Load"
        LoggeR "[ $NumchecK ] Processing Load details.." 1
        uptime | awk -F"load average" '{printf $2"\n"}' | awk -F":" '{printf $2"\n"}' | tr -d " " > $TmpfilE
        StatuS=$?
        ErrorchecK "Load Details"
        SetnumchecK
        HeaderstylE="DateTime,Load-1Min,Load-5Min,Load-15Min"

        if [ $DisplaY -eq 0 ]
        then
                cat $TmpfilE
                echo
        fi
        if [ ! -f $PERF_LOAD_OUT ]
        then
                echo "$HeaderstylE" > $PERF_LOAD_OUT
        else
                PreparenewfilE $PERF_LOAD_OUT
        fi
        echo -n "$CurrentdatE," >> $PERF_LOAD_OUT
        cat $TmpfilE   >> $PERF_LOAD_OUT
        tail -1 $PERF_LOAD_OUT > $TmpfilE_SNAPSHOT
        SnapshoT
}

#-- stat: Connection
ProcessconN()
{
        MonitortypE=$ConntypE
        LoggeR "[ $NumchecK ] Processing $ConntypE (`basename $ConnfilE`) Connection details.." 1
        TotalconN=`netstat -na | grep -w $ConnporT | grep -v \* | wc -l | awk -F" " '{printf $1"\n"}'`
        EstconN=`netstat -na | grep -w $ConnporT | grep ESTABLISHED | wc -l | awk -F" " '{printf $1"\n"}'`
        OtrconN=`echo $TotalconN - $EstconN | bc`
        StatuS=$?
        ErrorchecK "$ConntypE Connection Details"
        SetnumchecK

        HeaderstylE="DateTime,IPaddress,PORT,TotalConnection$ConnporT,ESTABLISHED,OTHER(CLOSE_WAIT:LAST_ACK:TIME_WAIT:etc)"

        if [ ! -f $ConnfilE ]
        then
                echo "$HeaderstylE" > $ConnfilE
        else
                VtemP=`grep ESTABLISHED $ConnfilE`
                if [ $? -eq 1 ]
                then
                        echo "$HeaderstylE" > $ConnfilE
                fi
        fi
        echo -n "$CurrentdatE",$ServeriP,$ConnporT >> $ConnfilE
        echo -n "," >> $ConnfilE
	
        echo $TotalconN,$EstconN,$OtrconN >> $ConnfilE

        tail -1 $ConnfilE > $TmpfilE_SNAPSHOT
        SnapshoT "$ConntypE Connection Details"
}

#-- stat: Connection Check
ConnectionchecK()
{
        ConntypE="$1"
        ConnporT="$2"
	ConnfilE=$PERF_PORT_PREFIX\_$ConntypE\_$ConnporT.csv

        ProcessconN
}

PERF_LsofuseR()
{
        UsertochecK="$1"
        LoggeR "[ $NumchecK ] Processing LSOF Usgae for user[$UsertochecK].." 1
        lsof | grep $UsertochecK | awk -F" " '{printf $1"\n"}' | sort | uniq -c | sort -g | sed 's/^/'`date +%d-%h-%Y[%H:%M:%S]`'/g' > $TmpfilE
        StatuS=$?
        ErrorchecK "LSOF User Check"
        SetnumchecK
        HeaderstylE="DateTime Count Service"

        ConnfilE_PREFIX=`echo $PERF_LSOF_USER_PREFIX | cut -d"." -f1`
        ConnfilE_POSTFIX=`echo $PERF_LSOF_USER_PREFIX | cut -d"." -f2`
        ConnfilE=$ConnfilE_PREFIX\_$UsertochecK.$ConnfilE_POSTFIX

        if [ ! -f $ConnfilE ]
        then
                echo "$HeaderstylE" > $ConnfilE
        else
                PreparenewfilE $ConnfilE
        fi
        echo -n "" >> $ConnfilE
        cat $TmpfilE >> $ConnfilE
        tail -1 $ConnfilE > $TmpfilE_SNAPSHOT
        SnapshoT "LSOF User Usage"
}

#-- stat: lsof all
PERF_LsofalL()
{
        UsertochecK="$1"
        LoggeR "[ $NumchecK ] Processing LSOF Usgae for ALL user.." 1
	LsoF=`which lsof`
        $LsoF | awk -F" " '{printf $3"\n"}' | sort | uniq -c | sort -g | tr -s " " | sed 's/ /,/g' | sed 's/^/'"$CurrentdatE"'/g' > $TmpfilE
        StatuS=$?
        ErrorchecK "LSOF ALL Check"
        SetnumchecK

        HeaderstylE="DateTime,Count,User"

        if [ ! -f $PERF_LSOF_ALL_OUT ]
        then
                echo "$HeaderstylE" > $PERF_LSOF_ALL_OUT
        else
                PreparenewfilE $PERF_LSOF_ALL_OUT
        fi
        echo -n "" >> $PERF_LSOF_ALL_OUT
        cat $TmpfilE >> $PERF_LSOF_ALL_OUT
        tail -1 $PERF_LSOF_ALL_OUT > $TmpfilE_SNAPSHOT
        SnapshoT "LSOF ALL Usage"
}

#-- stat: Disk Usage
PERF_DiskusagE()
{
	MonitortypE="Disk"
        LoggeR "[ $NumchecK ] Processing Disk Usgae.." 1
        df -Ph | tr -s " " | tr -d "%" | awk -F" " '{printf $1" "$6" "$5" "$2 " " $3" "$4"\n"}' | sort -nr -t" " -k 2 |grep -v Filesystem > $TmpfilE
        COUNT=$((`df -Ph|wc -l` - 1))
        StatuS=$?
        ErrorchecK "Disk Check"
        SetnumchecK
        HeaderstylE="DateTime,Disk_name,Mount_point,PercentageUsed,Total_size,used_size,available_size,disk_count"

        if [ ! -f $PERF_DU_OUT ]
        then
                echo "$HeaderstylE" > $PERF_DU_OUT
        else
                PreparenewfilE $PERF_DU_OUT
        fi
        while read line
        do

                echo -n "$CurrentdatE," >> $PERF_DU_OUT
                echo -n `echo $line | sed 's/ /,/g'`, >> $PERF_DU_OUT
                echo $COUNT >> $PERF_DU_OUT
        done < $TmpfilE
        tail -1 $PERF_DU_OUT > $TmpfilE_SNAPSHOT
        SnapshoT "Disk Usage"

}

#-- stat: INODE usage
PERF_InodeusagE()
{
        MonitortypE="Disk"
        LoggeR "[ $NumchecK ] Processing Disk Usgae.." 1
        df -ihP | tr -s " " | tr -d "%" | awk -F" " '{printf $1" "$6" "$5" "$2 " " $3" "$4"\n"}' | sort -nr -t" " -k 2 |grep -v Filesystem > $TmpfilE
        StatuS=$?
        ErrorchecK "Disk Check"
        SetnumchecK
        HeaderstylE="DateTime,Disk_name,Mount_point,IPercentageUsed,ITotal_size,Iused_size,Iavailable_size"

        if [ ! -f $PERF_INODE_OUT ]
        then
                echo "$HeaderstylE" > $PERF_INODE_OUT
        else
                PreparenewfilE $PERF_INODE_OUT
        fi
        while read line
        do
                echo -n "$CurrentdatE," >> $PERF_INODE_OUT
                echo `echo $line | sed 's/ /,/g'` >> $PERF_INODE_OUT
        done < $TmpfilE
        tail -1 $PERF_INODE_OUT > $TmpfilE_SNAPSHOT
        SnapshoT "Inode Usage"
}

PERF_UrlchecK()
{
        URL_TochecK="$1"

	echo $URL_TochecK | grep -e "http://" -e "https://" > $TmpfilE
	if [ $? -eq 0 ]
	then
	        PERF_UrlchecK_DOMAIN=`echo $URL_TochecK | awk -F/ '{print $3}'`
	else
	        PERF_UrlchecK_DOMAIN=`echo $URL_TochecK | awk -F/ '{print $1}'`
	fi
        UrltochecK_FILE=$PERF_URLCHECK_PREFIX\_$PERF_UrlchecK_DOMAIN

        MonitortypE="URL"
        LoggeR "Checking URL [ $URL_TochecK ] response time" 2
        curl -o /dev/null -s -w "%{time_total},%{time_namelookup},%{time_connect},%{time_appconnect},%{time_pretransfer},%{time_redirect},%{time_starttransfer}\\n"  "$URL_TochecK" > $TmpfilE
        StatuS=$?
        ErrorchecK "URL Response Time"

        SetnumchecK
        HeaderstylE="DateTime,time_total,time_namelookup,time_connect,time_appconnect,time_pretransfer,time_redirect,time_starttransfer"

        if [ ! -f $UrltochecK_FILE ]
        then
                echo "$HeaderstylE" > $UrltochecK_FILE
        else
                PreparenewfilE $UrltochecK_FILE
        fi
        echo -n `date +%d-%h-%Y[%H:%M:%S]`, >> $UrltochecK_FILE
        cat $TmpfilE >> $UrltochecK_FILE
        tail -1 $UrltochecK_FILE > $TmpfilE_SNAPSHOT
        SnapshoT "URL Check"
}

#-- stat: Filedescriptor
PERF_FdusagE()
{
        MonitortypE="FileDescriptor"
        LoggeR "[ $NumchecK ] Processing File descriptor.." 1
        LsofbiN=`which lsof`
        CurrentfD=`$LsofbiN | wc -l`
        StatuS=$?
        ErrorchecK "FileDescriptor"
        SetnumchecK
        HeaderstylE="DateTime,MaxFileDescriptor,CurrentUsage"

        if [ ! -f $PERF_FD_OUT ]
        then
                echo "$HeaderstylE" > $PERF_FD_OUT
        else
                VtemP=`grep MaxFileDescriptor $PERF_FD_OUT`
                if [ $? -eq 1 ]
                then
                        echo "$HeaderstylE" > $PERF_FD_OUT
                fi
        fi
        echo -n "$CurrentdatE," >> $PERF_FD_OUT
        echo `ulimit -n` $CurrentfD | sed 's/ /,/g' >> $PERF_FD_OUT
        tail -1 $PERF_FD_OUT > $TmpfilE_SNAPSHOT
        SnapshoT "FileDescriptor"
}

#-- stat: Iostat
PERF_IostatisticS()
{
        LoggeR "Collecting average record for $RecordseC Seconds. Please wait.." 2
        /usr/bin/iostat -k $RecordseC 2 > $PERF_IOSTAT_OUT
        StatuS=$?
        ErrorchecK "IOStat Details"
}

#-- stat: Jstat
PERF_JstaT()
{
        MonitortypE="Jstat"
        LoggeR "[ $NumchecK ] Processing Jstat.." 1
        TomcaT_PATH=/usr/local/tomcatwiki-5.5.29
        ps ax | grep "$TomcaT_PATH/" | grep java | grep -v grep | grep -v "tail -" | awk -F" " '{printf $1"\n"}' > $TmpfilE

        TomcatpiD=`cat $TmpfilE`
        N=`wc -l $TmpfilE | awk -F" " '{printf $1}'`
        if [ $N -eq 1 ]
        then
                jstat -gc -t $TomcatpiD | tail -1 | tr -s " " | sed 's/^ //g' > $TmpfilE
                StatuS=$?
                ErrorchecK "Jstat"
                SetnumchecK
                HeaderstylE="DateTime Timestamp S0C S1C S0U S1U EC EU OC OU PC PU YGC YGCT FGC FGCT GCT"

                if [ ! -f $PERF_JSTAT_OUT ]
                then
                        echo "$HeaderstylE" > $PERF_JSTAT_OUT
                else
                        PreparenewfilE $PERF_JSTAT_OUT
                fi
                echo -n "$CurrentdatE" >> $PERF_JSTAT_OUT
                echo -n " " >> $PERF_JSTAT_OUT
                cat $TmpfilE >> $PERF_JSTAT_OUT
                tail -1 $PERF_JSTAT_OUT > $TmpfilE_SNAPSHOT
                SnapshoT "JstaT"
        else
                LoggeR "[ WarN ] :: Tomcat is stopped" 5
        fi
}

#################################
# stat Capturing via SAR	#
#################################
VerifydaY()
{
	LoggeR "Checking for SAR report for the Day [ $SardaY ] " 1
	if [ $SardaY == "today" ]
	then
		SardaY=`date +%d`
	fi

	SarfilE=$SAR_DIR_SOURCE/sa$SardaY
	FilechecK $SarfilE f
	ErrorchecK		

	#-- Making copy of SAR binary file to process
	rm -rf $TmpfilE_SARBIN
	cp $SarfilE $TmpfilE_SARBIN
	
}

#-- Converting SAR output in CSV format
ConvertsartocsV()
{
	InputcsvfilE="$1"
	#-- 1: AM/PM, 2:DD-MM-YYY[HH:MM:ss]
	DatetimeformattypE=$2

	case $DatetimeformattypE in
	1)
		LoggeR "DateTime Format Type [ 12 Hours ] - Converting.." 0
		cat $InputcsvfilE | tr -s ' ' ',' | sed 's/,PM/ PM/g;s/,AM/ AM/g' | awk -v ExtravaR=$ServeriP 'BEGIN{FS=",";OFS=","}{"date -d\"" $1 "\" +%Y-%m-%d\\ %H:%M:%S" | getline datetime;$1=datetime","ExtravaR;print}' > $TmpfilE
		;;
	2)
		#-- For old stat data format
		LoggeR "DateTime Format Type [ 24 Hours but RAW ] - Converting.." 0
		cat $InputcsvfilE | tr -s ' ' ',' | sed 's/\[/ /g;s/\]//g' | awk -v ExtravaR=$ServeriP 'BEGIN{FS=",";OFS=","}{"date -d\"" $1 "\" +%Y-%m-%d\\ %H:%M:%S" | getline datetime;$1=datetime","ExtravaR;print}' > $TmpfilE
		;;
	*)
		LoggeR "UNKNOWN DateTime Format" 3
		;;
	esac

	rm -rf $InputcsvfilE
	mv $TmpfilE $InputcsvfilE
}

#-- SAR: CPU
SAR_CpU()
{
	LoggeR "Capturing SAR [ CPU ] data" 1
	HeadeR="DateTime,IPaddress,CPU,%user,%nice,%system,%iowait,%steal,%idle"

	sar -u -f $TmpfilE_SARBIN | cat | sed 1,3d | grep -v "Average" > $TmpfilE_SAR
	ConvertsartocsV $TmpfilE_SAR 1 ""

	echo "$HeadeR" > $SAR_CPU_OUT
	cat $TmpfilE_SAR >> $SAR_CPU_OUT
	#-- Need to add logic for multiple CPU
}

SAR_SystemloaD()
{
	LoggeR "Capturing SAR [ Load ] data" 1
	HeadeR="DateTime,IPaddress,runq-sz,plist-sz,ldavg-1,ldavg-5,ldavg-15"
	
	sar -q -f $TmpfilE_SARBIN | cat | sed 1,3d | grep -v "Average" > $TmpfilE_SAR
	ConvertsartocsV $TmpfilE_SAR 1 ""

	echo "$HeadeR" > $SAR_LOAD_OUT
	cat $TmpfilE_SAR >> $SAR_LOAD_OUT
}

NetworkprocesS()
{
	TypetoprocesS="$1"

	sar -n $TypetoprocesS -f $TmpfilE_SARBIN | cat | sed 1,3d | grep -v "Average" > $TmpfilE_SAR
	ConvertsartocsV $TmpfilE_SAR 1 ""
	
	N_InterfacE=`awk -F"," '{printf $3"\n"}' $TmpfilE_SAR | sort | uniq | wc -l`
	i_InterfacE=1
	for InterfacenamE in `awk -F"," '{printf $3"\n"}' $TmpfilE_SAR | sort | uniq`
	do
		LoggeR "| Interfaces [ $i_InterfacE/$N_InterfacE - $InterfacenamE ]" 1
		SarnetworkfilenamE=$SAR_NW_PREFIX\_$TypetoprocesS\_$InterfacenamE.csv
		
		echo "$HeadeR" > $SarnetworkfilenamE
		grep -w $InterfacenamE $TmpfilE_SAR >> $SarnetworkfilenamE

		i_InterfacE=`expr $i_InterfacE + 1`
	done
	rm -rf $TmpfilE_SAR
}

SAR_NetworK()
{
	LoggeR "Capturing SAR [ Network ] data" 1
	HeadeR="DateTime,IPaddress,IFACE,rxpck/s,txpck/s,rxkB/s,txkB/s,rxcmp/s,txcmp/s,rxmcst/s"
	NetworkprocesS DEV

	LoggeR "Capturing SAR [ Network ERROR] data" 1
	HeadeR="DateTime,IPaddress,IFACE,rxerr/s,txerr/s,coll/s,rxdrop/s,txdrop/s,txcarr/s,rxfram/s,rxfifo/s,txfifo/s"
	NetworkprocesS EDEV
}

CountlineS()
{
        FiletochecK="$1"
        N_FiletochecK=`wc -l $FiletochecK | awk -F" " '{printf $1"\n"}'`
        return $N_FiletochecK
}

RpmcheckalL()
{
        LoggeR "Collecting All RPM list from server" 2
        rpm -qa > $TmpfilE_ALLRPM
        CountlineS $TmpfilE_ALLRPM
        N_TmpfilE_ALLRPM=`echo $?`
        LoggeR "Total Number of RPM Found: $N_TmpfilE_ALLRPM" 4
}

ActiveporT()
{
        LoggeR "Collecting All Active ports from server" 2
        netstat -ntpl > $TmpfilE_NETSTAT
}
RunningprocesS()
{
        LoggeR "Collecting All Active process from server" 2
        ps aux > $TmpfilE_RUNNINGPROCESS
}

ProcesscapturE()
{
        PidtocapturE=$1
        OWNER=`grep -w $PidtocapturE $TmpfilE_RUNNINGPROCESS | awk -F" " '{printf $1"\n"}'`
        COMMAND=`grep -w $PidtocapturE $TmpfilE_RUNNINGPROCESS | awk -F" " '{printf $11"\n"}'`
}

PorttochecK()
{
	ServicetochecK="$1"
	grep -i $ServicetochecK $TmpfilE_NETSTAT | awk -F" " '{printf $7"\n"}' | sort | uniq > $TmpfilE
	CountlineS $TmpfilE
	N_PROCESS=`echo $?`

	if [ $N_PROCESS -ne "0" ]
	then
		for (( i_PROCESS=1;i_PROCESS<=$N_PROCESS;i_PROCESS++ ))
		do
			PID=`sed -ne ''$i_PROCESS','$i_PROCESS'p' $TmpfilE | awk -F"/" '{printf $1"\n"}'`
			PROCESS=`sed -ne ''$i_PROCESS','$i_PROCESS'p' $TmpfilE | awk -F"/" '{printf $2"\n"}'`
			PORT=`grep -w $PID $TmpfilE_NETSTAT | awk -F" " '{printf $4"\n"}' | awk -F":" '{printf $NF"\n"}' | tr '\n' ':' | sed 's/:$/\n/g'`
			ProcesscapturE $PID
                        HOST=$(ip addr | grep 'state UP' -A2 | tail -n1 | awk '{print $2}' | cut -f1  -d'/')
			ReportdatA=`echo $HOST,$PROCESS,$OWNER,$PID,$PORT,$COMMAND`
			LoggeR " | $ReportdatA" 1
			echo "$ReportdatA" >> $SW_PROCESS_OUT
		done
	else
		LoggeR " | No Active process found" 1
	fi
}

RpmchecK()
{
        RpmtochecK="$1"
        rm -rf $TmpfilE

        grep -i "$RpmtochecK" $TmpfilE_ALLRPM | tee $TmpfilE >> $SW_VERSION_OUT
        CountlineS $TmpfilE
        N_RPMCHECK=`echo $?`

        if [ $N_RPMCHECK -ne "0" ]
        then
                LoggeR " | RPM Check: $RpmtochecK ($N_RPMCHECK)" 1
                PorttochecK $RpmtochecK
        else
                LoggeR " | Skipping PORT check (Count=$N_RPMCHECK)" 4
        fi
}

ServersoftwarE()
{
	FilechecK $SW_PACKAGE_SOURCE f
	ErrorchecK "Software File Check"

        N_SW_PACKAGE_SOURCE=`wc -l $SW_PACKAGE_SOURCE | awk -F" " '{printf $1"\n"}'`
        LoggeR "Validating User defined software list ($N_SW_PACKAGE_SOURCE)" 2
        rm -rf $SW_PROCESS_OUT $SW_VERSION_OUT

        RpmcheckalL
        ActiveporT
        RunningprocesS

        for (( i_SW_PACKAGE_SOURCE=1;i_SW_PACKAGE_SOURCE<=$N_SW_PACKAGE_SOURCE;i_SW_PACKAGE_SOURCE++ ))
        do
                SoftwaretochecK=`sed -ne ''$i_SW_PACKAGE_SOURCE','$i_SW_PACKAGE_SOURCE'p' $SW_PACKAGE_SOURCE`
                LoggeR "[$i_SW_PACKAGE_SOURCE/$N_SW_PACKAGE_SOURCE] Filtering Software: $SoftwaretochecK" 1
                RpmchecK $SoftwaretochecK
        done
}

#################################
# Reporting functions           #
#################################
statdatA()
{
        clear
        LoggeR "#-------------------------------------------------#" 2
        LoggeR "[ Server stat as on `date '+%d-%h-%Y (%H:%M:%S)'` ]" 2
        LoggeR "#-------------------------------------------------#" 2

	#-- Resource Check
        PERF_IostatisticS

	#-- Number of Resources to Check: Initiaze with 1
        NumchecK=1
        rm -rf $PERF_SNAPSHOT

	#-- Start Capturing System Resources
        PERF_UserS
        PERF_MemorY
        PERF_CachE
        PERF_CpU
        PERF_DiskiO
        PERF_SystemloaD
        PERF_LsofalL
        PERF_LsofuseR root

	#-- Connection Check (1) Direct (2) with PORT_FILE
	if [ -f $PORT_FILE ]
	then
		LoggeR "[ $NumchecK.0 ] PORT_FILE Found. Checking Connection from PORT_FILE" 1
		while read line
		do
			PORT=$(echo $line |awk '{print $2}')
			APP=$(echo $line |awk '{print $1}')
		        ConnectionchecK $APP $PORT
		done < $PORT_FILE
	else
		LoggeR "[ $NumchecK.0 ] PORT_FILE Missing. Checking Connection from Script Configuration" 1
		ConnectionchecK ADMIN 9990
	fi

        PERF_DiskusagE
        PERF_InodeusagE
        PERF_FdusagE
	#PERF_UrlchecK "www.google.com"
	#PERF_UrlchecK "http://www.google.com"
        #PERF_JstaT
}

ServerstatS()
{
        clear
        LoggeR "#-------------------------------------------------#" 2
        LoggeR "[ Server Statistics report as on `date '+%d-%h-%Y (%H:%M:%S)'` ]" 2
        LoggeR "#-------------------------------------------------#" 2

	SS_RamdetailS
	SS_CpuarcH
	SS_RedhatreleasE
	SS_PuppeT
	SS_SymantecantiviruS
	SS_ProcessoR
	SS_ServeruptimE
	SS_InternetconN
	SS_TotaldisK
	SS_UseriD
	SS_OsbiT
	SS_GatewayiP
	SS_NTP
	SS_IptableS
	SS_OpenssL
	SS_LogiN
	SS_statruN

        PrepareserverstatsouT
}

CapturesaR()
{
	LoggeR "Capturing SAR output" 2	
	VerifydaY

	SAR_CpU
	SAR_SystemloaD
	SAR_NetworK
}

InitializereportinG()
{
	SetcurrentdatE

        case $DatatypE in
        "stat")
                statdatA ;;
        "serverstat")
                ServerstatS ;;
        "sar")
                CapturesaR ;;
        "serversoft")
                ServersoftwarE ;;
        *)
                LoggeR "Unknown Data Type for this script" 9 ;;
        esac

	case $UploaD in
	0)
		LoggeR "Currently Upload feature is DISABLED" 2 ;;
	1)
		LoggeR "Currently Upload feature is DISABLED" 2 ;;
	*)
		LoggeR "UNKNOWN Option" 2 ;;
	esac
}

####################################################
#               Initialising script                #
####################################################

ParamchecK $1 datatype
DatatypE=`echo $1 | grep "\-\-datatype="| cut -d"=" -f2`
BlankvaL $DatatypE

if [ $# -ne $MinparaM ]
then
        NumberofparaM=$#
        if [ $NumberofparaM -gt $MaxparaM ]
        then
                LoggeR "Maximum $MaxparaM parameters are allowed" 9
                UsagE
        fi

        MinparampluS=`echo $MinparaM + 1 | bc`
        for (( i_commandarg=$MinparampluS ; i_commandarg<=$NumberofparaM ; i_commandarg++ ))
        do
                ParamnamE=`echo ${!i_commandarg} | awk -F"--" '{printf $2"\n"}' | cut -d"=" -f1`
                if [ ! -z $ParamnamE ]
                then
                        case $ParamnamE in
                        "upload")
                                UploaD=`echo ${!i_commandarg} | grep "\-\-upload="| cut -d"=" -f2`
                                LoggeR "Setting Variable $ParamnamE=$UploaD" 0 ;;
                        "sarday")
                                SardaY=`echo ${!i_commandarg} | grep "\-\-sarday="| cut -d"=" -f2`
                                LoggeR "Setting Variable $ParamnamE=$SardaY" 0 ;;
                        *)
                                LoggeR "Unknown Parameter - $ParamnamE" 9
                                UsagE;;
                        esac
                else
                        LoggeR "Invalid Parameter Syntax - ${!i_commandarg}" 9
                        UsagE
                fi
        done
fi

#-- Checking default directories
CheckdiR $OutpuT_PATH
CheckdiR $TMP_DIRPATH

#-- Process Check
ProcesschecK

#-- Initialise Reporting
InitializereportinG

#-- Exit
ExitprocesS 0


