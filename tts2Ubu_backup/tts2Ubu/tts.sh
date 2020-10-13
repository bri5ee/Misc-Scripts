#!/bin/bash
echo "Welcome to Troy Tech Support"

USERS=./users.txt
ADMINS=./admins.txt

unleashHell(){
	starter
	dns
	#aptSettings
	verify
	users
	firewall
	misc
	filePriv
	lastMinuteChecks
}

#STARTER
starter(){
	checkCredentials
	saveLogs
	saveApt
	aliases
}

#Check for required files and credentials
checkCredentials(){
	if [[ $EUID -ne 0 ]]; then
   		echo "Troy Tech Support required admin priveleges. Get on our level"
   		exit 1
	fi

	if [ ! -f "$USERS" ]; then
    		echo "Necessary text files for users and admins are not present. Shutting down script."
    		exit 1
	fi

	if [ ! -f "$ADMINS" ]; then
    		echo "Necessary text files [admins] for users and admins are not present. Shutting down script."
    		exit 1
	fi
}

aliases(){
	#cat configs/bashrc > ~/.bashrc
	for user in $(cat users.txt); do
        	cat configs/bashrc > /home/$user/.bashrc;
	done;
	cat configs/bashrc > /root/.bashrc
	cat configs/profile > /etc/profile
}

saveLogs(){
	cp -r /var/log varLogBackups
}

saveApt(){
    cp -r /etc/apt aptBackups
}
#DNS
dns(){
	hosts
	resolv
	service network-manager restart
}

hosts(){
	echo "Configuring /etc/hosts file"

	echo "ALL:ALL" > /etc/hosts.deny
	echo "sshd:ALL" > /etc/hosts.allow

    #CHECK MANUALLy
	#echo 127.0.0.1 localhost > /etc/hosts
	#echo 127.0.1.1 $HOSTNAME  >> /etc/hosts
	#echo fe00::0 ip6-localnet >> /etc/hosts
	#echo ff00::0 ip6-mcastprefix >> /etc/hosts
	#echo ff02::1 ip6-allnodes >> /etc/hosts
	#echo ff02::2 ip6-allrouters >> /etc/hosts

	echo "resolver checks for spoofing"
	echo "order hosts,bind" > /etc/host.conf
	echo "multi on" >> /etc/host.conf
	echo "nospoof on" >> /etc/host.conf
}

resolv(){
	echo "Setting dns servers to google and cloudflare"
	cat configs/resolv.conf > /etc/resolv.conf
	cat configs/resolv.conf > /etc/resolvconf/resolv.conf.d/base
}

aptSettings(){
	echo "Setting automatic update checks"
	cat configs/10periodic > /etc/apt/apt.conf.d/10periodic
	cat configs/20auto-upgrades > /etc/apt/apt.conf.d/20auto-upgrades

	echo "Setting sources.list repositories"
	cat configs/sources.list > /etc/apt/sources.list
}

verify(){
	echo "checking the integrity of all packages using debsums"
	apt-get update > /dev/null
	apt-get install -y debsums
	apt-get install -y apt
	echo "fixing corrupt packages"
	apt-get install --reinstall $(dpkg -S $(debsums -c) | cut -d : -f 1 | sort -u)
	apt-get install --reinstall ufw libpam-cracklib procps net-tools findutils binutils coreutils
	echo "fixing files with missing files"
	xargs -rd '\n' -a <(sudo debsums -c 2>&1 | cut -d " " -f 4 | sort -u | xargs -rd '\n' -- dpkg -S | cut -d : -f 1 | sort -u) -- sudo apt-get install -f --reinstall --
	apt-get install -y ufw
	apt-get install -y libpam-cracklib
}

users(){
	configCmds
	checkAuthorized
	passwords
	lockAll
	rhosts
	hostsEquiv
	sudoers
	guestAcc
	passPolicy
}

configCmds(){
	cat configs/adduser.conf > /etc/adduser.conf
	cat configs/deluser.conf > /etc/deluser.conf
}

#Creates all required users and deletes those that aren't
checkAuthorized(){

	#For everyone in users.txt file, creates the user
	for user in $(cat users.txt); do
		grep -q $user /etc/passwd || useradd -m -s /bin/bash $user
		crontab -u $user -r
		echo "$user checked for existence"
	done
	echo "Finished adding users"

	#Delete bad users
	for user in $(grep "bash" /etc/passwd | cut -d':' -f1); do
		grep -q $user users.txt || (deluser $user 2> /dev/null)
	done
	echo "Finished deleting bad users"


	#this script is kinda wack
	#but basically, it will delete admins, including correct ones, and then add them back in
	#Goes and makes users admin/not admin as needed for every user with UID above 500 that has a home directory
	for i in $(cat /etc/passwd | cut -d: -f 1,3,6 | grep -e "[5-9][0-9][0-9]" -e "[0-9][0-9][0-9][0-9]" | grep "/home" | cut -d: -f1); do
		#If the user is supposed to be a normal user but is in the sudo group, remove them from sudo
		BadUser=0
		if [[ $( grep -ic $i $(pwd)/users.txt ) -ne 0 ]]; then
			if [[ $( echo $( grep "sudo" /etc/group) | grep -ic $i ) -ne 0 ]]; then
				#if username is in sudo when shouldn’t
				deluser $i sudo;
			fi
			if [[ $( echo $( grep "adm" /etc/group) | grep -ic $i ) -ne 0 ]]; then
				#if username is in adm when shouldn’t
				deluser $i adm;
			fi
		else
			BadUser=$((BadUser+1));
		fi
		#If user is supposed to be an adm but isn’t, raise privilege.

		if [[ $( grep -ic $i $(pwd)/admins.txt ) -ne 0 ]]; then
			if [[ $( echo $( grep "sudo" /etc/group) | grep -ic $i ) -eq 0 ]]; then
				#if username isn't in sudo when should
				usermod -a -G "sudo" $i
			fi
			if [[ $( echo $( grep "adm" /etc/group) | grep -ic $i ) -eq 0 ]]; then
				#if username isn't in adm when should
				usermod -a -G "adm" $i
			fi
		else
			BadUser=$((BadUser+1));
		fi

		if [[ $BadUser -eq 2 ]]; then
			echo "WARNING: USER $i HAS AN ID THAT IS CONSISTENT WITH A NEWLY ADDED USER YET IS NOT MENTIONED IN EITHER THE admins.txt OR users.txt FILE. LOOK INTO THIS."
		fi
	done

	echo "Finished changing users"
}

passwords()
{
	echo "settings password and locking root"
	echo 'root:CyberPatriot!!123' | chpasswd;
	passwd -l root;
	echo "change all user passwords"
	for user in $(cat users.txt); do
		passwd -q -x 85 $user > /dev/null;
		passwd -q -n 15 $user > /dev/null;
		echo $user':CyberPatriot!!123' | chpasswd;
		chage --maxdays 15 --mindays 6 --warndays 7 --inactive 5 $user;
	done;
}

lockAll()
{
	echo "locking all system accounts"
	for user in $(cat /etc/passwd | cut -d ':' -f 1); do
		echo $user;
		grep -q $user users.txt || grep -q $user admins.txt || passwd -l $user;
	done;
}

rhosts()
{
	echo "deleting rhosts files"
	find / -name ".rhosts" -exec rm -rf {} \;
}

hostsEquiv()
{
	echo "deleting hosts.equiv files"
	find / -name "hosts.equiv" -exec rm -rf {} \;
}

sudoers(){
	echo "Resetting sudoers file and README"
	cat configs/sudoers > /etc/sudoers
	cat configs/README > /etc/sudoers.d/README
}

guestAcc(){
	echo "Disabling guest account"
	cat configs/lightdm.conf > /etc/lightdm/lightdm.conf

}

passPolicy(){
	echo "Setting password policy"
	
	cat configs/login.defs > /etc/login.defs

	cat configs/common-password > /etc/pam.d/common-password
	cat configs/common-auth > /etc/pam.d/common-auth
	
	echo "Password policy has been set"
	
}

firewall()
{
	echo "setting firewall"
	#ufw --force reset
	ufw enable
	ufw default allow outgoing
	ufw default deny incoming
	ufw logging high
	#ipfun
	ufw enable
}

filePriv()
{
	df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t

	bash helperScripts/perms.sh
}
ipfun()
{
	bash helperScripts/ipfun.sh
}

misc()
{
	dconfSettings
	echo "* hard core 0" > /etc/security/limits.conf
	echo "tmpfs /run/shm tmpfs defaults,nodev,noexec,nosuid 0 0" >> /etc/fstab
	echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
	echo "tmpfs /var/tmp tmpfs defaults,nodev,noexec,nosuid 0 0" >> /etc/fstab
	prelink -ua
	apt-get remove -y prelink
	systemctl mask ctrl-alt-del.target
	systemctl daemon-reload
	echo "tty1" > /etc/securetty
	echo "TMOUT=300" >> /etc/profile
	echo "readonly TMOUT" >> /etc/profile
	echo "export TMOUT" >> /etc/profile
	#dont prune shit lol
	echo "" > /etc/updatedb.conf
	echo "blacklist usb-storage" >> /etc/modprobe.d/blacklist.conf
	echo "install usb-storage /bin/false" > /etc/modprobe.d/usb-storage.conf
	cat configs/environment > /etc/environment
	cat configs/control-alt-delete.conf > /etc/init/control-alt-delete.conf
	apt-get install -y auditd > /dev/null
	auditctl -e 1
}	

dconfSettings()
{
	dconf reset -f /
	gsettings set org.gnome.desktop.privacy remember-recent-files false
	gsettings set org.gnome.desktop.media-handling automount false
	gsettings set org.gnome.desktop.media-handling automount-open false
	gsettings set org.gnome.desktop.search-providers disable-external true
	dconf update /

}

lastMinuteChecks()
{
	#soltuion: /boot/config-$(uname -r) should contain CONFIG_PAGE_TABLE_ISOLATION
	#apt-get update && apt install linux-image-generic
	dmesg | grep "Kernel/User page tables isolation: enabled" && echo "patched" || echo "unpatched"

	cat /etc/default/grub | grep "selinux" && echo "check /etc/default/grub for selinux" || echo "/etc/default/grub does not disable selinux"

	cat /etc/default/grub | grep "enforcing=0" && echo "check /etc/default/grub for enforcing" || echo "/etc/default/grub does not contain enforcing=0"
}




unleashHell
