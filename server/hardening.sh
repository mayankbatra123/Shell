#!/bin/bash
#########################################################
# This script will be used for server hardening		#					#
#                                                       #
# Date Created: 20171123                                #
#########################################################

#MAIN_PATH=/data/admin/scripts/InsertIntoDB
MAIN_PATH_D="L2RhdGEvYWRtaW4vc2NyaXB0cy9Oc2F0b29ML2hhcmRlbmluZwo="
MAIN_PATH=`echo ${MAIN_PATH_D} | base64 --decode`
source ~/.bash_profile
source $MAIN_PATH/.creds

#-- Variables for the script
MinparaM=1
MaxparaM=7
DisplaY=0
localGroup="project_admin"
adGroup="linux_server_admin"
ROOT_PASS=`date +%s | sha256sum | base64 | head -c 8;`
os="linux"
action="verify"
rootpass="no"

### Credential to check AD
PSWD1="<>"
SERVER_USER1="jsag"


#-- Base Path where script is deployed
BASE_PATH=<>
LogpatH=$BASE_PATH/hardening/hardening.log
ConfigureAD=$BASE_PATH/buttonclicks/ConfigureADPBIS.yml
OutputPath=$BASE_PATH/hardening/output/hardening.csv

export SERVER_USER=`echo ${SERVER_USER}| base64 --decode`
export PSWD=`echo ${PSWD} | base64 --decode`
export ULDAP=`echo ${ULDAP} | base64 --decode`
export PLDAP=`echo ${PLDAP}| base64 --decode`

if [[ -f $OutputPath ]]
then
	rm -f $OutputPath
fi

hostname_format ()
{
        host_to_check=`sshpass -p $PSWD ssh -o ConnectTimeout=10 -o LogLevel=QUIET -o StrictHostKeyChecking=no $SERVER_USER@$IP_TO_CHECK "hostname"` 2>/dev/null
	if [[ $? -eq 0 ]]
	then
		export err=0
		if [[ ${host_to_check,,} == devnag-* ]] && [[ ${class,,} == "dev" ]]
		then
			export host_format_check="YES"
			export host_format_desc="Hostname Verified - Dev Server [ ${host_to_check} ]"
			export err=0
		elif [[ ${host_to_check,,} == orgnag-* ]] && [[ ${class,,} == "prod" ]]
		then
			export host_format_check="YES"
			export host_format_desc="Hostname Verified - Prod Server [ ${host_to_check} ]"
			export err=0
		else
			export host_format_check="NO"
			export host_format_desc="Hostname Format Incorrect - [ ${host_to_check} ]"
			export err=3
		fi
	else
		export err=3
		export host_format_check="NO"
		export host_format_desc="Hostname Not Set"
	fi
	LoggeR "Verify Hardening : $host_format_desc" $err

}

user_ad_check ()
{

        ad_check_value=`sshpass -p $PSWD1 ssh -ttt -o ConnectTimeout=10 -o LogLevel=QUIET -o StrictHostKeyChecking=no $SERVER_USER1@$IP_TO_CHECK "echo hello"` 2>/dev/null
	if [[ $? -eq 0 ]]
        then
		if [[ ${class,,} == "dev" ]]
		then
                	export ad_auth_check="YES"
                	export ad_auth_desc="AD Authentication verified"
                	LoggeR "Verify Hardening : $ad_auth_desc" 0
		else
			disableAd 
		fi
        else
		if [[ ${class,,} == "prod" ]]
		then
			export ad_auth_check="NO"
			export ad_auth_desc="AD Authentication failed. Since it is prod server."
                	LoggeR "Verify Hardening : $ad_auth_desc" 0
		else
			fixAD  
		fi		

        fi


}

ntp_status ()
{

	sshpass -p $PSWD ssh -ttt -o ConnectTimeout=10 -o StrictHostKeyChecking=no $SERVER_USER@$IP_TO_CHECK "sudo service ntpd status | grep -i running " > /dev/null 2>&1 
	if [[ $? -eq 0 ]]
        then
                ntp_check="YES"
		ntp_desc="NTP status verified"
		LoggeR "Verify Hardening : $ntp_desc" 0
        else
		fixNtp_rpm	
        fi

}
ntp_ubuntu ()
{

        sshpass -p $PSWD ssh -ttt -o ConnectTimeout=10 -o StrictHostKeyChecking=no $SERVER_USER@$IP_TO_CHECK "sudo service ntp status" > /dev/null 2>&1
        if [[ $? -eq 0 ]]
        then
                ntp_ubuntu_check="YES"
                ntp_ubuntu_desc="NTP status verified"
                LoggeR "Verify Hardening : $ntp_ubuntu_desc" 0
        else
		fixNtp_ubuntu
        fi

}

sysstat_rpm ()
{

	sysstat_check=`sshpass -p $PSWD ssh -o ConnectTimeout=10 -o LogLevel=QUIET -o StrictHostKeyChecking=no $SERVER_USER@$IP_TO_CHECK "rpm -qa | grep sysstat"` 2>/dev/null
	
	if [[ $? -eq 0 ]]
	then
		export sysstat_rpm_check="YES"
		export sysstat_rpm_desc="Sysstat RPM Verified with version - $sysstat_check"
		LoggeR "Verify Hardening : $sysstat_rpm_desc" 0
	else
		fixSysstat_rpm 
	fi

}


sysstat_ubuntu ()
{

        sysstat_check_ubuntu=`sshpass -p $PSWD ssh -t -o ConnectTimeout=10 -o LogLevel=QUIET -o StrictHostKeyChecking=no $SERVER_USER@$IP_TO_CHECK "sudo dpkg -l sysstat"` 2>/dev/null

        if [[ $? -eq 0 ]]
        then
                export sysstat_ubuntu_check="YES"
                export sysstat_ubuntu_desc="Sysstat Verified"
                LoggeR "Verify Hardening : $sysstat_ubuntu_desc" 0
        else
                export sysstat_ubuntu_check="NO"
                export sysstat_ubuntu_desc="Sysstat Missing"
                LoggeR "Verify Hardening : $sysstat_ubuntu_desc" 3
        fi

}


openssl_version ()
{

	openssl_check=`sshpass -p $PSWD ssh -o ConnectTimeout=10 -o LogLevel=QUIET -o StrictHostKeyChecking=no  $SERVER_USER@$IP_TO_CHECK "openssl version"` 2>/dev/null
	if [[ $? -eq 0 ]]
        then
                export openssl_value_check="YES"
		export openssl_value_desc="Openssl Verified with version - $openssl_check"
		LoggeR "Verify Hardening : $openssl_value_desc" 0
        else
		fixOpenssl_rpm 
        fi
}


openssl_ubuntu ()
{

        openssl_check_ubuntu=`sshpass -p $PSWD ssh -t -o ConnectTimeout=10 -o LogLevel=QUIET -o StrictHostKeyChecking=no $SERVER_USER@$IP_TO_CHECK "sudo dpkg -l openssl"` 2>/dev/null

        if [[ $? -eq 0 ]]
        then
                export openssl_ubuntu_check="YES"
                export openssl_ubuntu_desc="Openssl Verified"
                LoggeR "Verify Hardening : $openssl_ubuntu_desc" 0
        else
		fixOpenssl_ubuntu 
        fi

}


user_sudo_check ()
{

        sshpass -p $PSWD ssh -ttt -o ConnectTimeout=10 -o LogLevel=QUIET -o StrictHostKeyChecking=no $SERVER_USER@$IP_TO_CHECK "sudo -v" > /dev/null 2>&1
	if [[ $? -eq 0 ]]
	then
		export user_sudo_check="YES"
		export user_sudo_desc="$SERVER_USER has sudo access check"
		LoggeR "Verify Hardening : $user_sudo_desc" 0
	else
		export user_sudo_check="NO"
		export user_sudo_desc="$SERVER_USER does not have sudo access check"
		LoggeR "Verify Hardening : $user_sudo_desc" 3
	fi
}

local_group_status ()
{

        sshpass -p $PSWD ssh -ttt -o ConnectTimeout=10 -o LogLevel=QUIET -o StrictHostKeyChecking=no $SERVER_USER@$IP_TO_CHECK "sudo grep -qwi $localGroup /etc/sudoers;" > /dev/null 2>&1
        if [[ $? -eq 0 ]]
        then
                export local_group_check="YES"
                export local_group_desc="$localGroup Group is verified"
                LoggeR "Verify Hardening : $local_group_desc" 0
        else
		add_localgroup 
        fi
}

ad_group_status ()
{

        sshpass -p $PSWD ssh -ttt -o ConnectTimeout=10 -o LogLevel=QUIET -o StrictHostKeyChecking=no $SERVER_USER@$IP_TO_CHECK "sudo grep -qwi $adGroup /etc/sudoers" > /dev/null 2>&1
        if [[ $? -eq 0 ]]
        then
                export ad_group_check="YES"
                export ad_group_desc="$adGroup Group is verified"
                LoggeR "Verify Hardening : $ad_group_desc" 0
        else
		add_adgroup 
        fi


}

mysql_insert ()
{

echo "Future Use"
#mysql -h $HOST -u $USER -p$PASS -e "use $DB_NAME; insert into verify_hardening values(DEFAULT,'$IP','$host_format_check','$openssl_value_check','$ntp_check','$sysstat_rpm_check','$ad_auth_check','$user_sudo_check','HOSTNAME - $host_to_check',NOW()); "

#echo "mysql -h $HOST -u $USER -p$PASS -e use $DB_NAME; insert into server_listing(server_id,server_ip,server_hostname,scm_admin_user,ad_access,ntp_check,openSSH_version,created_on) values(DEFAULT,'$IP','$host_format_check','$user_sudo_check','$ad_auth_check','$ntp_check',NOW());  "

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
                #-- Usage Info
                MessageheadeR=Usage
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

Usage()
{
        echo
        echo "[ Usage ] :: sh $0 --ip=<10.10.10.10> --action=<fix/verify> --class=<dev/prod> --os=<ubuntu/linux>  [ --type=<ad/sysstat/openssl/nagpackage/localgroup/adgroup>--user=<scmadmin> --pass=<user pass> --rootpass=<yes/no>]"
        echo "---------------------------------------------------------"
        echo " | ip(10.10.101.10) : Pass any IP Address"
        echo " |--------------------------------------------------------"
        echo " | action(verify) : Verify server hardening and also fix the same."
	echo " | action(fix) : If need to fix a specific property [ --type must be passed ]"
        echo "----------------------------------------------------------"
        echo " | class(dev) : For dev servers"
        echo " | class(prod) : For production servers "
        echo "----------------------------------------------------------"
	echo " | type parameter is mandatory if --action=fix"
	echo " | type(ad) : If need to fix ad"
        echo " | type(openssl) : If need to fix openssl  "
        echo " | type(sysstat) : If need to fix sysstat  "
        echo " | type(localgroup) : If need to fix local group missing issue  "
        echo " | type(adgroup) : If need to fix ad group missing issue "
        echo " | type(nagpackage) : If need to fix missing nag rpm [ performance,logrotate] "
        echo "----------------------------------------------------------"
	echo " | os(ubuntu) : Script will be executed as per Ubuntu OS   "
	echo " | os(linux) : Script be executed as per linux OS "
	echo "----------------------------------------------------------"
	echo " | rootpass(yes) : Change root password   "
	echo " | rootpass(no) : Do no change root password   "
        exit 1
}


disableAd ()
{

	sshpass -p $PSWD ssh -t -o ConnectTimeout=10 -o StrictHostKeyChecking=no $SERVER_USER@$IP_TO_CHECK "sudo su root  bash -c 'sudo service lwsmd stop' " > /dev/null 2>&1
	if [[ $? -eq 0 ]]
        then
                export ad_auth_check="NO"
                ad_fix="AD Configuration Disabled Successfully"
                LoggeR "Fix Hardening : $ad_fix" 0
        else
                export ad_auth_check="YES"
                ad_fix="AD Configuration Disbling Failed. [PROD SERVER]"
                LoggeR "Fix Hardening : $ad_fix" 4
        fi

}

fixAD ()
{

        sshpass -p $PSWD ssh -t -o ConnectTimeout=10 -o StrictHostKeyChecking=no $SERVER_USER@$IP_TO_CHECK "sudo su root  bash -c 'yum install -y pbis-open ;wget -O /tmp http://repo.pbis.beyondtrust.com/apt/RPM-GPG-KEY-pbis ;apt-key add /tmp/RPM-GPG-KEY-pbis ; wget -O /etc/apt/sources.list.d/pbiso.list http://repo.pbis.beyondtrust.com/apt/pbiso.list ; apt-get update ;apt-get install pbis-open ;sed -i '/centrify/s/^/#/g' /etc/pam.d/system-auth;sed -i '/centrify/s/^/#/g' /etc/pam.d/system-auth-ac;sed -i '/centrify/s/^/#/g' /etc/pam.d/password-auth;sed -i '/centrify/s/^/#/g' /etc/pam.d/su;service lwsmd restart;domainjoin-cli join <domain> $ULDAP $PLDAP;/opt/pbis/bin/config HomeDirTemplate %H/%U;/opt/pbis/bin/config LoginShellTemplate /bin/bash;/opt/pbis/bin/config AssumeDefaultDomain true' " > /dev/null 2>&1
        if [[ $? -eq 0 ]]
        then
		export ad_auth_check="YES"
                ad_fix="AD Configuration completed"
		LoggeR "Fix Hardening : $ad_fix" 0
        else
		export ad_auth_check="NO"
		ad_fix="AD Configuration Failed. Critical - since it is DEV server."
                LoggeR "Fix Hardening : $ad_fix" 4
        fi


}

add_localgroup ()
{
	sshpass -p $PSWD ssh -ttt -o ConnectTimeout=10 -o StrictHostKeyChecking=no $SERVER_USER@$IP_TO_CHECK  "sudo su root bash -c ' groupadd $localGroup;echo %\"$localGroup ALL=(ALL)       NOPASSWD: ALL\" >> /etc/sudoers '" > /dev/null 2>&1
	if [[ $? -eq 0 ]]
        then
		export local_group_check="YES"
                localGroup_fix="Local Group - $localGroup created"
                LoggeR "Fix Hardening : $localGroup_fix" 0
        else
		export local_group_check="NO"
                localGroup_fix="Local group Creation - $localGroup failed."
                LoggeR "Fix Hardening : $localGroup_fix" 4
        fi

}

add_adgroup ()
{
        sshpass -p $PSWD ssh -ttt -o ConnectTimeout=10 -o StrictHostKeyChecking=no $SERVER_USER@$IP_TO_CHECK  "sudo su root bash -c 'echo %\"$adGroup ALL=(ALL)       NOPASSWD: ALL\" >> /etc/sudoers '" > /dev/null 2>&1
        if [[ $? -eq 0 ]]
        then
		export ad_group_check="YES"
                adGroup_fix="AD Group - $adGroup created"
                LoggeR "Fix Hardening : $adGroup_fix" 0
        else
		export ad_group_check="NO"
                adGroup_fix="AD group Creation - $adGroup failed."
                LoggeR "Fix Hardening : $adGroup_fix" 4
        fi

}

fixSysstat_rpm ()
{

        sshpass -p $PSWD ssh -ttt -o ConnectTimeout=10 -o StrictHostKeyChecking=no $SERVER_USER@$IP_TO_CHECK  "sudo yum -y install sysstat" > /dev/null 2>&1
        if [[ $? -eq 0 ]]
        then
                export sysstat_rpm_check="YES"
                export sysstat_rpm_desc="Sysstat RPM Verified with version - $sysstat_check"
                LoggeR "Fix Hardening : $sysstat_rpm_desc" 0
        else
		export sysstat_rpm_check="NO"
                export sysstat_rpm_desc="Sysstat RPM Installation Failed"
                LoggeR "Fix Hardening : $sysstat_rpm_desc" 4                
        fi

}

fixOpenssl_ubuntu ()
{

        sshpass -p $PSWD ssh -ttt -o ConnectTimeout=10 -o StrictHostKeyChecking=no $SERVER_USER@$IP_TO_CHECK "sudo apt-get install openssl" > /dev/null 2>&1
	if [[ $? -eq 0 ]]
        then
                export openssl_ubuntu_check="YES"
                export openssl_ubuntu_desc="Openssl Installed."
                LoggeR "Fix Hardening : $openssl_ubuntu_desc" 0
        else
                export openssl_ubuntu_check="NO"
                export openssl_ubuntu_desc="Openssl Installation Failed"
                LoggeR "Fix Hardening : $openssl_ubuntu_desc" 4
        fi

}
fixOpenssl_rpm ()
{

        sshpass -p $PSWD ssh -ttt -o ConnectTimeout=10 -o StrictHostKeyChecking=no $SERVER_USER@$IP_TO_CHECK  "sudo yum -y install openssl" > /dev/null 2>&1
        if [[ $? -eq 0 ]]
        then
                export openssl_value_check="YES"
                export openssl_desc_check="Openssl Verified with version - $openssl_value_check"
                LoggeR "Fix Hardening : $openssl_desc_check" 0
        else
                export openssl_value_check="NO"
                export openssl_value_desc="Sysstat RPM Installation Failed"
                LoggeR "Fix Hardening : $openssl_desc_check" 4
        fi

}


check_antivirus ()
{

	sshpass -p $PSWD  ssh -ttt -o StrictHostKeyChecking=no $SERVER_USER@$IP_TO_CHECK "sudo service ma status" > /dev/null 2>&1
	if [[ $? -eq 0 ]]
        then
		export check_antivirus_value="YES"
                export check_antivirus_desc="Antivirus Mcafee is Verified"
                LoggeR "Verify Hardening : $check_antivirus_desc" 0
	else
		#sshpass -p $PSWD scp /data/admin/scripts/Antivirus/agentPackages.zip $SERVER_USER@$IP_TO_CHECK:/tmp > /dev/null 2>&1
		sshpass -p $PSWD ssh -ttt -o ConnectTimeout=10 -o StrictHostKeyChecking=no $SERVER_USER@$IP_TO_CHECK  "yum -y install MAProvision "	> /dev/null 2>&1
		if [[ $? -eq 0 ]]
		then
			export check_antivirus_value="YES"
                	export check_antivirus_value="Antivirus Mcafee is Installed"
                	LoggeR "Fix Hardening : $check_antivirus_value" 0
		else
			export check_antivirus_value="NO"
                        export check_antivirus_value="Antivirus Mcafee Installation Failed"
                        LoggeR "Fix Hardening : $check_antivirus_value" 4
		fi
	fi
}

fixNtp_rpm ()
{

        sshpass -p $PSWD ssh -ttt -o ConnectTimeout=10 -o StrictHostKeyChecking=no $SERVER_USER@$IP_TO_CHECK "yum -y install ntp" > /dev/null 2>&1
        sshpass -p $PSWD scp /etc/ntp.conf $SERVER_USER@$IP_TO_CHECK:/tmp/
        sshpass -p $PSWD ssh -ttt -o ConnectTimeout=10 -o StrictHostKeyChecking=no $SERVER_USER@$IP_TO_CHECK "sudo mv /tmp/ntp.conf /etc/ ;sudo service ntpd restart " > /dev/null 2>&1
        if [[ $? -eq 0 ]]
        then
                ntp_check="YES"
                ntp_desc="NTP Installed and Configured"
                LoggeR "Fix Hardening : $ntp_desc" 0
        else
                ntp_check="No"
                ntp_desc="NTP installation failed"
                LoggeR "Fix Hardening : $ntp_desc" 4
        fi
}



fixNtp_ubuntu ()
{

	sshpass -p $PSWD ssh -ttt -o ConnectTimeout=10 -o StrictHostKeyChecking=no $SERVER_USER@$IP_TO_CHECK "sudo apt-get install ntpd" > /dev/null 2>&1
	sshpass -p $PSWD scp /etc/ntp.conf $SERVER_USER@$IP_TO_CHECK:/etc/
	sshpass -p $PSWD ssh -ttt -o ConnectTimeout=10 -o StrictHostKeyChecking=no $SERVER_USER@$IP_TO_CHECK "sudo mv /tmp/ntp.conf /etc/ ;sudo service ntp restart " > /dev/null 2>&1
	if [[ $? -eq 0 ]]
        then
                ntp_ubuntu_check="YES"
                ntp_ubuntu_desc="NTP Installed and Configured"
                LoggeR "Fix Hardening : $ntp_ubuntu_desc" 0
        else
		ntp_ubuntu_check="No"
                ntp_ubuntu_desc="NTP installation failed"
                LoggeR "Fix Hardening : $ntp_ubuntu_desc" 4
	fi
}

changeRootPass ()
{

	sshpass -p $PSWD  ssh -ttt -o StrictHostKeyChecking=no $SERVER_USER@$IP_TO_CHECK echo ${ROOT_PASS}  \| sudo passwd root --stdin > /dev/null 2>&1
	if [[ $? -eq 0 ]]
	then
		echo "${ROOT_PASS}"
		LoggeR "Fix Hardening : Root Password Changed - ${ROOT_PASS}" 0
	
	else
		 LoggeR "Fix Hardening : Unable to change root password - ${ROOT_PASS}" 4
	fi

}

#######Initializing the script 
if [[ $# -gt $MinparaM ]]
then 
	NumberofparaM=$#
        if [ $NumberofparaM -gt $MaxparaM ]
        then
                LoggeR "Maximum $MaxparaM parameters are allowed" 9
                Usage
        fi
	for (( cmdArg=$MinparaM ; cmdArg<=$NumberofparaM ; cmdArg++ ))
	do
			ParamnamE=`echo ${!cmdArg} | awk -F"--" '{printf $2"\n"}' | cut -d"=" -f1`
			if [ ! -z $ParamnamE ]
                	then
				case $ParamnamE in
                        "ip")
                               export  ip=`echo ${!cmdArg} | grep "\-\-ip="| cut -d"=" -f2` 
                               LoggeR "Setting Variable $ParamnamE=$ip" 0 ;;
			"user")
				export SERVER_USER=`echo ${!cmdArg} | grep "\-\-user="| cut -d"=" -f2` 
				 LoggeR "Setting Variable $ParamnamE=$SERVER_USER" 0 ;;
			"pass")
                                export PSWD=`echo ${!cmdArg} | grep "\-\-pass="| cut -d"=" -f2`
                                 LoggeR "Setting Variable $ParamnamE=$PSWD" 0 ;;
			"class")
                                export class=`echo ${!cmdArg} | grep "\-\-class="| cut -d"=" -f2`
                                LoggeR "Setting Variable $ParamnamE=$class" 0 ;;
			"os")
				export os=`echo ${!cmdArg} | grep "\-\-os="| cut -d"=" -f2`
				LoggeR "Setting Variable $ParamnamE=$os" 0 ;;
			"action")
                                export action=`echo ${!cmdArg} | grep "\-\-action="| cut -d"=" -f2`
                                LoggeR "Setting Variable $ParamnamE=$action" 0 ;;
			"type")
                                export type=`echo ${!cmdArg} | grep "\-\-type="| cut -d"=" -f2`
                                LoggeR "Setting Variable $ParamnamE=$type" 0 ;;
			"rootpass")
				export rootpass=`echo ${!cmdArg} | grep "\-\-rootpass="| cut -d"=" -f2`
                                LoggeR "Setting Variable $ParamnamE=$rootpass" 0 ;;
                        *)
                               LoggeR "Unknown Parameter - $ParamnamE" 9
                               Usage;;
                        esac	
				
			fi
	done
	if [ ! -z $ip ]
        then
		ping -c1 $ip > /dev/null 2>&1
       		if [[ $? -eq 0 ]]
		then
			export IP_TO_CHECK=$ip
			if [[ ${os,,} == "linux" ]]
			then
				if [[ ${action,,} == "verify" ]]
				then
					user_ad_check 
					user_sudo_check
					hostname_format 
					sysstat_rpm 
					openssl_version 
					ntp_status 
					local_group_status 
					ad_group_status
					check_antivirus
					if [[ ${rootpass,,} == "yes" ]]
					then
						changeRootPass
					fi 
					echo -ne "IP_ADDRESS,AD_CHECK,HOSTNAME_CHECK,SUDO_CHECK,SYSSTAT_CHECK,OPENSSL_CHECK,NTP_CHECK,LOCAL_GROUP,AD_GROUP,NAG_PERFORMANCE,NAG_LOGROTATE,ANTIVIRUS_CHECK \n" >> $OutputPath
					echo -ne "$ip,$ad_auth_check,$host_format_check,$user_sudo_check,$sysstat_rpm_check,$openssl_value_check,$ntp_check,$local_group_check,$ad_group_check,$performance_rpm_value,$logrotate_rpm_value,$check_antivirus_value" >> $OutputPath
				elif [[ ${action,,} == "fix" ]]
				then
					case $type in
					"ad")
                              			user_ad_check ;;
					"sysstat")	
						sysstat_rpm ;;
					"openssl")
						openssl_version ;;
					"localgroup")
						local_group_status;;
					"adgroup")
						ad_group_status ;;
					*)
                               			LoggeR "Unknown Parameter - $type" 9
                              			Usage;;
				esac
	
				fi

			elif [[ ${os,,} == "ubuntu" ]]
			then
				if [[ ${action,,} == "verify" ]]
				then
					user_ad_check
					user_sudo_check 
                                	hostname_format 
					sysstat_ubuntu 
                                	openssl_ubuntu 
                               	 	ntp_ubuntu 
                                	local_group_status 
					ad_group_status
					check_antivirus
					if [[ ${rootpass,,} == "yes" ]]
                                        then
                                                changeRootPass
                                        fi 
                                	echo -ne "IP_ADDRESS,AD_CHECK,HOSTNAME_CHECK,SUDO_CHECK,SYSSTAT_CHECK,OPENSSL_CHECK,NTP_CHECK,LOCAL_GROUP,,NAG_PERFORMANCE,NAG_LOGROTATE,ANTIVIRUS_CHECK \n" >> $OutputPath
                                	echo -ne "$ip,$ad_auth_check,$host_format_check,$user_sudo_check,$sysstat_ubuntu_check,$openssl_ubuntu_check,$ntp_ubuntu_check,$local_group_check,$performance_ubuntu_value,$logrotate_ubuntu_value,$check_antivirus_value" >> $OutputPath
				elif [[ ${action,,} == "fix" ]]
                                then
                                        case $type in
                                        "ad")
                                                user_ad_check ;;
                                        "sysstat")
                                                sysstat_ubuntu ;;
                                        "openssl")
                                                openssl_ubuntu ;;
                                        "localgroup")
                                                local_group_status;;
                                        "adgroup")
                                                ad_group_status ;;
                                        *)
                                                LoggeR "Unknown Parameter - $type" 9
                                                Usage;;
                                esac

                                fi

			fi
		else

			LoggeR " $ip : is Down " 9
			Usage
		fi
		
	fi
		
else
	Usage	
fi
