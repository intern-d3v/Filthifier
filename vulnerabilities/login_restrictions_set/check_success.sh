grep "auth required pam_tally2.so" /etc/pam.d/common-auth | grep deny= | grep -Po "([3-6])" 
