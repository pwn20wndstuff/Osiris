echo Removing Message-of-the-Day
/jb/bin/rm /etc/motd
echo Removing /.cydia_no_stash
/jb/bin/rm /.cydia_no_stash 
echo Removing Cydia
/jb/bin/rm -fR /Applications/Cydia.app/
echo Removing Filza
/jb/bin/rm -fR /Applications/Filza.app/
echo Removing terminfo database
/jb/bin/rm -fR /usr/share/terminfo
echo Removing ZSH support files
/jb/bin/rm -fR /usr/local/lib/zsh
/jb/bin/rm /bin/zsh
/jb/bin/rm /etc/zshrc

echo Removing J-tools from /usr/local/bin
/jb/bin/rm -fR /usr/local/bin

echo Removing /usr/bin/scp as well. This means you can\'t use WinSCP, etc anymore.
/jb/bin/rm /usr/bin/scp

echo Reenabling mesu.apple.com \(for auto-updates and/or stock app downloads\)
/jb/bin/cat /etc/hosts | /jb/bin/grep -v mesu > /tmp/hosts.tmp
/jb/bin/mv /tmp/hosts.tmp /etc/hosts
/jb/bin/rm -fR /var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdate
/jb/bin/mkdir -p /var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdate
/jb/bin/chmod 0755 /var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdate
/jb/usr/sbin/chown root:wheel /var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdate
/jb/bin/mkdir -p /var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdateDocumentation
/jb/bin/chmod 0755 /var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdateDocumentation
/jb/usr/sbin/chown root:wheel /var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdateDocumentation

echo Removing /jb
/jb/bin/rm -fR /jb

echo Sad to see you go.. but - That\'s it - no traces should be left. 
echo You cannot do anything else in the shell since the binaries have all been removed. 
echo Reboot your device to stop dropbear. 
