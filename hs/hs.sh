
USERS=users.txt
ADMINS=admins.txt

#Check for sudo, user text file, and admin text file
if [ [ $EUID -ne 0 ] ]; then
        echo "Need sudo privs before executing script."
        exit 1
fi
# Check for users file
if [ ! -f "$USERS" ]; then
        echo "Need user text file"
        exit 1
fi

#Check for admin file
if [ ! -f "$ADMINS" ]; then
        echo "Need admins text file"
        exit 1
fi

# Add users / check for existing users
echo "Add users / check for existing users"
echo "  "
for user in $(cat users.txt); do
        grep -q $user /etc/passwd || useradd -m -s /bin/bash $user
        crontab -u $user -r
        echo "$user checked for existence"
done
echo "Finished adding users"
echo " "

# Remove any users from sudoers group
echo "Remove any users from sudoers group"
echo "  "
for user in $(cat users.txt); do
        sudo deluser $user sudo
done
echo "Finished removing sudoers group from all users."
echo " "

# Add admins to sudoers group
echo "Add admins to sudoers group"
echo "  "
for admin in $(cat admins.txt); do
        sudo usermod -aG sudo $admin
        echo "$admin added to sudoers group."
done
echo "Finished adding admins to sudoers group."
echo " "

# Remove software
echo "Remove unneeded software packages"
echo "   "
for software in $(cat software-list.txt); do
        echo "Removing $software package [script]."
        sudo apt autoremove --purge $software -y
done

#Changing root password and locking root
echo "Changing root password and locking root"
echo "  "
sudo sh -c 'echo root:SWIFTSec1234!@#$ | chpasswd'
sudo passwd -l root

#Change passwords for all users | UID >= 1000
echo "Changing passwords for all users | UID >= 1000"
echo "  "
awk -F':' '{ if($3 >= 1000) print $1 }' /etc/passwd | sed 's/$/:SWIFTSec1234!@#$/' | chpasswd
