#!/bin/bash
#from this: https://static.open-scap.org/ssg-guides/ssg-rhel7-guide-stig_gui.html

# Find which files have incorrect hash (not in /etc, because of the system related config files) and then get files names
files_with_incorrect_hash="$(rpm -Va --noconfig | grep -E '^..5' | awk '{print $NF}' )"
# From files names get package names and change newline to space, because rpm writes each package to new line
packages_to_reinstall="$(rpm -qf $files_with_incorrect_hash | tr '\n' ' ')"
dnf reinstall -y $packages_to_reinstall
systemctl enable --now firewalld

# Declare array to hold set of RPM packages we need to correct permissions for
declare -A SETPERMS_RPM_DICT
# Create a list of files on the system having permissions different from what
# is expected by the RPM database
readarray -t FILES_WITH_INCORRECT_PERMS < <(rpm -Va --nofiledigest | awk '{ if (substr($0,6,1)=="U" || substr($0,7,1)=="G") print $NF }')
for FILE_PATH in "${FILES_WITH_INCORRECT_PERMS[@]}"
do
        RPM_PACKAGE=$(rpm -qf "$FILE_PATH")
	# Use an associative array to store packages as it's keys, not having to care about duplicates.
	SETPERMS_RPM_DICT["$RPM_PACKAGE"]=1
done
# For each of the RPM packages left in the list -- reset its permissions to the
# correct values
for RPM_PACKAGE in "${!SETPERMS_RPM_DICT[@]}"
do
        rpm --setugids "${RPM_PACKAGE}"
done

# Declare array to hold set of RPM packages we need to correct permissions for
declare -A SETPERMS_RPM_DICT
# Create a list of files on the system having permissions different from what
# is expected by the RPM database
readarray -t FILES_WITH_INCORRECT_PERMS < <(rpm -Va --nofiledigest | awk '{ if (substr($0,2,1)=="M") print $NF }')
for FILE_PATH in "${FILES_WITH_INCORRECT_PERMS[@]}"
do
        # NOTE: some files maybe controlled by more then one package
        readarray -t RPM_PACKAGES < <(rpm -qf "${FILE_PATH}")
        for RPM_PACKAGE in "${RPM_PACKAGES[@]}"
        do
                # Use an associative array to store packages as it's keys, not having to care about duplicates.
                SETPERMS_RPM_DICT["$RPM_PACKAGE"]=1
        done
done
# For each of the RPM packages left in the list -- reset its permissions to the
# correct values
for RPM_PACKAGE in "${!SETPERMS_RPM_DICT[@]}"
do
	rpm --restore "${RPM_PACKAGE}"
done

# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
if ! rpm -q --quiet "aide" ; then
    dnf install -y "aide"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
if ! rpm -q --quiet "aide" ; then
    dnf install -y "aide"
fi
/usr/sbin/aide --init
/bin/cp -p /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
if ! rpm -q --quiet "aide" ; then
    dnf install -y "aide"
fi
if ! rpm -q --quiet "crontabs" ; then
    dnf install -y "crontabs"
fi
if ! grep -q "/usr/sbin/aide --check" /etc/crontab ; then
    echo "05 4 * * * root /usr/sbin/aide --check" >> /etc/crontab
else
    sed -i '\!^.* --check.*$!d' /etc/crontab
    echo "05 4 * * * root /usr/sbin/aide --check" >> /etc/crontab
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
if ! rpm -q --quiet "aide" ; then
    dnf install -y "aide"
fi
if ! rpm -q --quiet "crontabs" ; then
    dnf install -y "crontabs"
fi
var_aide_scan_notification_email='root@localhost'
CRONTAB=/etc/crontab
CRONDIRS='/etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.monthly'
# NOTE: on some platforms, /etc/crontab may not exist
if [ -f /etc/crontab ]; then
	CRONTAB_EXIST=/etc/crontab
fi

if [ -f /var/spool/cron/root ]; then
	VARSPOOL=/var/spool/cron/root
fi

if ! grep -qR '^.*/usr/sbin/aide\s*\-\-check.*|.*\/bin\/mail\s*-s\s*".*"\s*.*@.*$' $CRONTAB_EXIST $VARSPOOL $CRONDIRS; then
	echo "0 5 * * * root /usr/sbin/aide  --check | /bin/mail -s \"\$(hostname) - AIDE Integrity Check\" $var_aide_scan_notification_email" >> $CRONTAB
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
if ! rpm -q --quiet "aide" ; then
    dnf install -y "aide"
fi
aide_conf="/etc/aide.conf"
forbidden_hashes=(sha1 rmd160 sha256 whirlpool tiger haval gost crc32)
groups=$(LC_ALL=C grep "^[A-Z][A-Za-z_]*" $aide_conf | cut -f1 -d ' ' | tr -d ' ' | sort -u)
for group in $groups
do
	config=$(grep "^$group\s*=" $aide_conf | cut -f2 -d '=' | tr -d ' ')

	if ! [[ $config = *sha512* ]]
	then
		config=$config"+sha512"
	fi

	for hash in "${forbidden_hashes[@]}"
	do
		config=$(echo $config | sed "s/$hash//")
	done

	config=$(echo $config | sed "s/^\+*//")
	config=$(echo $config | sed "s/\+\++/+/")
	config=$(echo $config | sed "s/\+$//")

	sed -i "s/^$group\s*=.*/$group = $config/g" $aide_conf
done
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
if ! rpm -q --quiet "aide" ; then
    dnf install -y "aide"
fi
aide_conf="/etc/aide.conf"
groups=$(LC_ALL=C grep "^[A-Z][A-Za-z_]*" $aide_conf | grep -v "^ALLXTRAHASHES" | cut -f1 -d '=' | tr -d ' ' | sort -u)
for group in $groups
do
	config=$(grep "^$group\s*=" $aide_conf | cut -f2 -d '=' | tr -d ' ')

	if ! [[ $config = *acl* ]]
	then
		if [[ -z $config ]]
		then
			config="acl"
		else
			config=$config"+acl"
		fi
	fi
	sed -i "s/^$group\s*=.*/$group = $config/g" $aide_conf
done
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
if ! rpm -q --quiet "aide" ; then
    dnf install -y "aide"
fi
aide_conf="/etc/aide.conf"
groups=$(LC_ALL=C grep "^[A-Z][A-Za-z_]*" $aide_conf | grep -v "^ALLXTRAHASHES" | cut -f1 -d '=' | tr -d ' ' | sort -u)
for group in $groups
do
	config=$(grep "^$group\s*=" $aide_conf | cut -f2 -d '=' | tr -d ' ')

	if ! [[ $config = *xattrs* ]]
	then
		if [[ -z $config ]]
		then
			config="xattrs"
		else
			config=$config"+xattrs"
		fi
	fi
	sed -i "s/^$group\s*=.*/$group = $config/g" $aide_conf
done
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Remediation is applicable only in certain platforms
if ( [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && ! ( [ "${container:-}" == "bwrap-osbuild" ] ) ) && { rpm --quiet -q grub2-common; }; then
# prelink not installed
if test -e /etc/sysconfig/prelink -o -e /usr/sbin/prelink; then
    if grep -q ^PRELINKING /etc/sysconfig/prelink
    then
        sed -i 's/^PRELINKING[:blank:]*=[:blank:]*[:alpha:]*/PRELINKING=no/' /etc/sysconfig/prelink
    else
        printf '\n' >> /etc/sysconfig/prelink
        printf '%s\n' '# Set PRELINKING=no per security requirements' 'PRELINKING=no' >> /etc/sysconfig/prelink
    fi

    # Undo previous prelink changes to binaries if prelink is available.
    if test -x /usr/sbin/prelink; then
        /usr/sbin/prelink -ua
    fi
fi
if grep -q -m1 -o aes /proc/cpuinfo; then
	if ! rpm -q --quiet "dracut-fips-aesni" ; then
    dnf install -y "dracut-fips-aesni"
fi
fi
if ! rpm -q --quiet "dracut-fips" ; then
    dnf install -y "dracut-fips"
fi
dracut -f
# Correct the form of default kernel command line in  grub
if grep -q '^GRUB_CMDLINE_LINUX=.*fips=.*"'  /etc/default/grub; then
	# modify the GRUB command-line if a fips= arg already exists
	sed -i 's/\(^GRUB_CMDLINE_LINUX=".*\)fips=[^[:space:]]*\(.*"\)/\1 fips=1 \2/'  /etc/default/grub
else
	# no existing fips=arg is present, append it
	sed -i 's/\(^GRUB_CMDLINE_LINUX=".*\)"/\1 fips=1"/'  /etc/default/grub
fi
# Get the UUID of the device mounted at root (/).
ROOT_UUID=$(findmnt --noheadings --output uuid --target /)
# Get the UUID of the device mounted at /boot.
BOOT_UUID=$(findmnt --noheadings --output uuid --target /boot)
if [ "${ROOT_UUID}" == "${BOOT_UUID}" ]; then
	# root UUID same as boot UUID, so do not modify the GRUB command-line or add boot arg to kernel command line
	# Correct the form of kernel command line for each installed kernel in the bootloader
	/sbin/grubby --update-kernel=ALL --args="fips=1"
else
	# root UUID different from boot UUID, so modify the GRUB command-line and add boot arg to kernel command line
	if grep -q '^GRUB_CMDLINE_LINUX=".*boot=.*"'  /etc/default/grub; then
		# modify the GRUB command-line if a boot= arg already exists
		sed -i 's/\(^GRUB_CMDLINE_LINUX=".*\)boot=[^[:space:]]*\(.*"\)/\1 boot=UUID='"${BOOT_UUID} \2/" /etc/default/grub
	else
		# no existing boot=arg is present, append it
		sed -i 's/\(^GRUB_CMDLINE_LINUX=".*\)"/\1 boot=UUID='${BOOT_UUID}'"/'  /etc/default/grub
	fi
	# Correct the form of kernel command line for each installed kernel in the bootloader
	/sbin/grubby --update-kernel=ALL --args="fips=1 boot=UUID=${BOOT_UUID}"
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then
# Check for setting in any of the DConf db directories
# If files contain ibus or distro, ignore them.
# The assignment assumes that individual filenames don't contain :
readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/login-screen\\]" "/etc/dconf/db/" \
                                | grep -v 'distro\|ibus\|gdm.d' | cut -d":" -f1)
DCONFFILE="/etc/dconf/db/gdm.d/00-security-settings"
DBDIR="/etc/dconf/db/gdm.d"
mkdir -p "${DBDIR}"
# Comment out the configurations in databases different from the target one
if [ "${#SETTINGSFILES[@]}" -ne 0 ]
then
    if grep -q "^\\s*enable-smartcard-authentication\\s*=" "${SETTINGSFILES[@]}"
    then
        
        sed -Ei "s/(^\s*)enable-smartcard-authentication(\s*=)/#\1enable-smartcard-authentication\2/g" "${SETTINGSFILES[@]}"
    fi
fi
[ ! -z "${DCONFFILE}" ] && echo "" >> "${DCONFFILE}"
if ! grep -q "\\[org/gnome/login-screen\\]" "${DCONFFILE}"
then
    printf '%s\n' "[org/gnome/login-screen]" >> ${DCONFFILE}
fi
escaped_value="$(sed -e 's/\\/\\\\/g' <<< "true")"
if grep -q "^\\s*enable-smartcard-authentication\\s*=" "${DCONFFILE}"
then
        sed -i "s/\\s*enable-smartcard-authentication\\s*=\\s*.*/enable-smartcard-authentication=${escaped_value}/g" "${DCONFFILE}"
    else
        sed -i "\\|\\[org/gnome/login-screen\\]|a\\enable-smartcard-authentication=${escaped_value}" "${DCONFFILE}"
fi
dconf update
# Check for setting in any of the DConf db directories
LOCKFILES=$(grep -r "^/org/gnome/login-screen/enable-smartcard-authentication$" "/etc/dconf/db/" \
            | grep -v 'distro\|ibus\|gdm.d' | grep ":" | cut -d":" -f1)
LOCKSFOLDER="/etc/dconf/db/gdm.d/locks"
mkdir -p "${LOCKSFOLDER}"
# Comment out the configurations in databases different from the target one
if [[ ! -z "${LOCKFILES}" ]]
then
    sed -i -E "s|^/org/gnome/login-screen/enable-smartcard-authentication$|#&|" "${LOCKFILES[@]}"
fi
if ! grep -qr "^/org/gnome/login-screen/enable-smartcard-authentication$" /etc/dconf/db/gdm.d/
then
    echo "/org/gnome/login-screen/enable-smartcard-authentication" >> "/etc/dconf/db/gdm.d/locks/00-security-settings-lock"
fi
dconf update
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then
if rpm --quiet -q gdm
then
	if ! grep -q "^AutomaticLoginEnable=" /etc/gdm/custom.conf
	then
		sed -i "/^\[daemon\]/a \
		AutomaticLoginEnable=False" /etc/gdm/custom.conf
	else
		sed -i "s/^AutomaticLoginEnable=.*/AutomaticLoginEnable=False/g" /etc/gdm/custom.conf
	fi
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then
if rpm --quiet -q gdm
then
	if ! grep -q "^TimedLoginEnable=" /etc/gdm/custom.conf
	then
		sed -i "/^\[daemon\]/a \
		TimedLoginEnable=false" /etc/gdm/custom.conf
	else
		sed -i "s/^TimedLoginEnable=.*/TimedLoginEnable=false/g" /etc/gdm/custom.conf
	fi
fi
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then
# Check for setting in any of the DConf db directories
# If files contain ibus or distro, ignore them.
# The assignment assumes that individual filenames don't contain :
readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/desktop/media-handling\\]" "/etc/dconf/db/" \
                                | grep -v 'distro\|ibus\|local.d' | cut -d":" -f1)
DCONFFILE="/etc/dconf/db/local.d/00-security-settings"
DBDIR="/etc/dconf/db/local.d"
mkdir -p "${DBDIR}"
# Comment out the configurations in databases different from the target one
if [ "${#SETTINGSFILES[@]}" -ne 0 ]
then
    if grep -q "^\\s*automount\\s*=" "${SETTINGSFILES[@]}"
    then
        
        sed -Ei "s/(^\s*)automount(\s*=)/#\1automount\2/g" "${SETTINGSFILES[@]}"
    fi
fi
[ ! -z "${DCONFFILE}" ] && echo "" >> "${DCONFFILE}"
if ! grep -q "\\[org/gnome/desktop/media-handling\\]" "${DCONFFILE}"
then
    printf '%s\n' "[org/gnome/desktop/media-handling]" >> ${DCONFFILE}
fi
escaped_value="$(sed -e 's/\\/\\\\/g' <<< "false")"
if grep -q "^\\s*automount\\s*=" "${DCONFFILE}"
then
        sed -i "s/\\s*automount\\s*=\\s*.*/automount=${escaped_value}/g" "${DCONFFILE}"
    else
        sed -i "\\|\\[org/gnome/desktop/media-handling\\]|a\\automount=${escaped_value}" "${DCONFFILE}"
fi
dconf update
# Check for setting in any of the DConf db directories
LOCKFILES=$(grep -r "^/org/gnome/desktop/media-handling/automount$" "/etc/dconf/db/" \
            | grep -v 'distro\|ibus\|local.d' | grep ":" | cut -d":" -f1)
LOCKSFOLDER="/etc/dconf/db/local.d/locks"
mkdir -p "${LOCKSFOLDER}"
# Comment out the configurations in databases different from the target one
if [[ ! -z "${LOCKFILES}" ]]
then
    sed -i -E "s|^/org/gnome/desktop/media-handling/automount$|#&|" "${LOCKFILES[@]}"
fi
if ! grep -qr "^/org/gnome/desktop/media-handling/automount$" /etc/dconf/db/local.d/
then
    echo "/org/gnome/desktop/media-handling/automount" >> "/etc/dconf/db/local.d/locks/00-security-settings-lock"
fi
dconf update
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

# Check for setting in any of the DConf db directories
# If files contain ibus or distro, ignore them.
# The assignment assumes that individual filenames don't contain :
readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/desktop/media-handling\\]" "/etc/dconf/db/" \
                                | grep -v 'distro\|ibus\|local.d' | cut -d":" -f1)
DCONFFILE="/etc/dconf/db/local.d/00-security-settings"
DBDIR="/etc/dconf/db/local.d"

mkdir -p "${DBDIR}"

# Comment out the configurations in databases different from the target one
if [ "${#SETTINGSFILES[@]}" -ne 0 ]
then
    if grep -q "^\\s*automount-open\\s*=" "${SETTINGSFILES[@]}"
    then
        
        sed -Ei "s/(^\s*)automount-open(\s*=)/#\1automount-open\2/g" "${SETTINGSFILES[@]}"
    fi
fi


[ ! -z "${DCONFFILE}" ] && echo "" >> "${DCONFFILE}"
if ! grep -q "\\[org/gnome/desktop/media-handling\\]" "${DCONFFILE}"
then
    printf '%s\n' "[org/gnome/desktop/media-handling]" >> ${DCONFFILE}
fi

escaped_value="$(sed -e 's/\\/\\\\/g' <<< "false")"
if grep -q "^\\s*automount-open\\s*=" "${DCONFFILE}"
then
        sed -i "s/\\s*automount-open\\s*=\\s*.*/automount-open=${escaped_value}/g" "${DCONFFILE}"
    else
        sed -i "\\|\\[org/gnome/desktop/media-handling\\]|a\\automount-open=${escaped_value}" "${DCONFFILE}"
fi

dconf update
# Check for setting in any of the DConf db directories
LOCKFILES=$(grep -r "^/org/gnome/desktop/media-handling/automount-open$" "/etc/dconf/db/" \
            | grep -v 'distro\|ibus\|local.d' | grep ":" | cut -d":" -f1)
LOCKSFOLDER="/etc/dconf/db/local.d/locks"

mkdir -p "${LOCKSFOLDER}"

# Comment out the configurations in databases different from the target one
if [[ ! -z "${LOCKFILES}" ]]
then
    sed -i -E "s|^/org/gnome/desktop/media-handling/automount-open$|#&|" "${LOCKFILES[@]}"
fi

if ! grep -qr "^/org/gnome/desktop/media-handling/automount-open$" /etc/dconf/db/local.d/
then
    echo "/org/gnome/desktop/media-handling/automount-open" >> "/etc/dconf/db/local.d/locks/00-security-settings-lock"
fi

dconf update

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

# Check for setting in any of the DConf db directories
# If files contain ibus or distro, ignore them.
# The assignment assumes that individual filenames don't contain :
readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/desktop/media-handling\\]" "/etc/dconf/db/" \
                                | grep -v 'distro\|ibus\|local.d' | cut -d":" -f1)
DCONFFILE="/etc/dconf/db/local.d/00-security-settings"
DBDIR="/etc/dconf/db/local.d"

mkdir -p "${DBDIR}"

# Comment out the configurations in databases different from the target one
if [ "${#SETTINGSFILES[@]}" -ne 0 ]
then
    if grep -q "^\\s*autorun-never\\s*=" "${SETTINGSFILES[@]}"
    then
        
        sed -Ei "s/(^\s*)autorun-never(\s*=)/#\1autorun-never\2/g" "${SETTINGSFILES[@]}"
    fi
fi


[ ! -z "${DCONFFILE}" ] && echo "" >> "${DCONFFILE}"
if ! grep -q "\\[org/gnome/desktop/media-handling\\]" "${DCONFFILE}"
then
    printf '%s\n' "[org/gnome/desktop/media-handling]" >> ${DCONFFILE}
fi

escaped_value="$(sed -e 's/\\/\\\\/g' <<< "true")"
if grep -q "^\\s*autorun-never\\s*=" "${DCONFFILE}"
then
        sed -i "s/\\s*autorun-never\\s*=\\s*.*/autorun-never=${escaped_value}/g" "${DCONFFILE}"
    else
        sed -i "\\|\\[org/gnome/desktop/media-handling\\]|a\\autorun-never=${escaped_value}" "${DCONFFILE}"
fi

dconf update
# Check for setting in any of the DConf db directories
LOCKFILES=$(grep -r "^/org/gnome/desktop/media-handling/autorun-never$" "/etc/dconf/db/" \
            | grep -v 'distro\|ibus\|local.d' | grep ":" | cut -d":" -f1)
LOCKSFOLDER="/etc/dconf/db/local.d/locks"

mkdir -p "${LOCKSFOLDER}"

# Comment out the configurations in databases different from the target one
if [[ ! -z "${LOCKFILES}" ]]
then
    sed -i -E "s|^/org/gnome/desktop/media-handling/autorun-never$|#&|" "${LOCKFILES[@]}"
fi

if ! grep -qr "^/org/gnome/desktop/media-handling/autorun-never$" /etc/dconf/db/local.d/
then
    echo "/org/gnome/desktop/media-handling/autorun-never" >> "/etc/dconf/db/local.d/locks/00-security-settings-lock"
fi

dconf update

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

# Check for setting in any of the DConf db directories
# If files contain ibus or distro, ignore them.
# The assignment assumes that individual filenames don't contain :
readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/desktop/screensaver\\]" "/etc/dconf/db/" \
                                | grep -v 'distro\|ibus\|local.d' | cut -d":" -f1)
DCONFFILE="/etc/dconf/db/local.d/00-security-settings"
DBDIR="/etc/dconf/db/local.d"

mkdir -p "${DBDIR}"

# Comment out the configurations in databases different from the target one
if [ "${#SETTINGSFILES[@]}" -ne 0 ]
then
    if grep -q "^\\s*idle-activation-enabled\\s*=" "${SETTINGSFILES[@]}"
    then
        
        sed -Ei "s/(^\s*)idle-activation-enabled(\s*=)/#\1idle-activation-enabled\2/g" "${SETTINGSFILES[@]}"
    fi
fi


[ ! -z "${DCONFFILE}" ] && echo "" >> "${DCONFFILE}"
if ! grep -q "\\[org/gnome/desktop/screensaver\\]" "${DCONFFILE}"
then
    printf '%s\n' "[org/gnome/desktop/screensaver]" >> ${DCONFFILE}
fi

escaped_value="$(sed -e 's/\\/\\\\/g' <<< "true")"
if grep -q "^\\s*idle-activation-enabled\\s*=" "${DCONFFILE}"
then
        sed -i "s/\\s*idle-activation-enabled\\s*=\\s*.*/idle-activation-enabled=${escaped_value}/g" "${DCONFFILE}"
    else
        sed -i "\\|\\[org/gnome/desktop/screensaver\\]|a\\idle-activation-enabled=${escaped_value}" "${DCONFFILE}"
fi

dconf update
# Check for setting in any of the DConf db directories
LOCKFILES=$(grep -r "^/org/gnome/desktop/screensaver/idle-activation-enabled$" "/etc/dconf/db/" \
            | grep -v 'distro\|ibus\|local.d' | grep ":" | cut -d":" -f1)
LOCKSFOLDER="/etc/dconf/db/local.d/locks"

mkdir -p "${LOCKSFOLDER}"

# Comment out the configurations in databases different from the target one
if [[ ! -z "${LOCKFILES}" ]]
then
    sed -i -E "s|^/org/gnome/desktop/screensaver/idle-activation-enabled$|#&|" "${LOCKFILES[@]}"
fi

if ! grep -qr "^/org/gnome/desktop/screensaver/idle-activation-enabled$" /etc/dconf/db/local.d/
then
    echo "/org/gnome/desktop/screensaver/idle-activation-enabled" >> "/etc/dconf/db/local.d/locks/00-security-settings-lock"
fi

dconf update

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm; then

# Check for setting in any of the DConf db directories
LOCKFILES=$(grep -r "^/org/gnome/desktop/screensaver/idle-activation-enabled$" "/etc/dconf/db/" \
            | grep -v 'distro\|ibus\|local.d' | grep ":" | cut -d":" -f1)
LOCKSFOLDER="/etc/dconf/db/local.d/locks"

mkdir -p "${LOCKSFOLDER}"

# Comment out the configurations in databases different from the target one
if [[ ! -z "${LOCKFILES}" ]]
then
    sed -i -E "s|^/org/gnome/desktop/screensaver/idle-activation-enabled$|#&|" "${LOCKFILES[@]}"
fi

if ! grep -qr "^/org/gnome/desktop/screensaver/idle-activation-enabled$" /etc/dconf/db/local.d/
then
    echo "/org/gnome/desktop/screensaver/idle-activation-enabled" >> "/etc/dconf/db/local.d/locks/00-security-settings-lock"
fi

dconf update

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

inactivity_timeout_value='900'


# Check for setting in any of the DConf db directories
# If files contain ibus or distro, ignore them.
# The assignment assumes that individual filenames don't contain :
readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/desktop/session\\]" "/etc/dconf/db/" \
                                | grep -v 'distro\|ibus\|local.d' | cut -d":" -f1)
DCONFFILE="/etc/dconf/db/local.d/00-security-settings"
DBDIR="/etc/dconf/db/local.d"

mkdir -p "${DBDIR}"

# Comment out the configurations in databases different from the target one
if [ "${#SETTINGSFILES[@]}" -ne 0 ]
then
    if grep -q "^\\s*idle-delay\\s*=" "${SETTINGSFILES[@]}"
    then
        
        sed -Ei "s/(^\s*)idle-delay(\s*=)/#\1idle-delay\2/g" "${SETTINGSFILES[@]}"
    fi
fi


[ ! -z "${DCONFFILE}" ] && echo "" >> "${DCONFFILE}"
if ! grep -q "\\[org/gnome/desktop/session\\]" "${DCONFFILE}"
then
    printf '%s\n' "[org/gnome/desktop/session]" >> ${DCONFFILE}
fi

escaped_value="$(sed -e 's/\\/\\\\/g' <<< "uint32 ${inactivity_timeout_value}")"
if grep -q "^\\s*idle-delay\\s*=" "${DCONFFILE}"
then
        sed -i "s/\\s*idle-delay\\s*=\\s*.*/idle-delay=${escaped_value}/g" "${DCONFFILE}"
    else
        sed -i "\\|\\[org/gnome/desktop/session\\]|a\\idle-delay=${escaped_value}" "${DCONFFILE}"
fi

dconf update

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi


# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

var_screensaver_lock_delay='5'


# Check for setting in any of the DConf db directories
# If files contain ibus or distro, ignore them.
# The assignment assumes that individual filenames don't contain :
readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/desktop/screensaver\\]" "/etc/dconf/db/" \
                                | grep -v 'distro\|ibus\|local.d' | cut -d":" -f1)
DCONFFILE="/etc/dconf/db/local.d/00-security-settings"
DBDIR="/etc/dconf/db/local.d"

mkdir -p "${DBDIR}"

# Comment out the configurations in databases different from the target one
if [ "${#SETTINGSFILES[@]}" -ne 0 ]
then
    if grep -q "^\\s*lock-delay\\s*=" "${SETTINGSFILES[@]}"
    then
        
        sed -Ei "s/(^\s*)lock-delay(\s*=)/#\1lock-delay\2/g" "${SETTINGSFILES[@]}"
    fi
fi


[ ! -z "${DCONFFILE}" ] && echo "" >> "${DCONFFILE}"
if ! grep -q "\\[org/gnome/desktop/screensaver\\]" "${DCONFFILE}"
then
    printf '%s\n' "[org/gnome/desktop/screensaver]" >> ${DCONFFILE}
fi

escaped_value="$(sed -e 's/\\/\\\\/g' <<< "uint32 ${var_screensaver_lock_delay}")"
if grep -q "^\\s*lock-delay\\s*=" "${DCONFFILE}"
then
        sed -i "s/\\s*lock-delay\\s*=\\s*.*/lock-delay=${escaped_value}/g" "${DCONFFILE}"
    else
        sed -i "\\|\\[org/gnome/desktop/screensaver\\]|a\\lock-delay=${escaped_value}" "${DCONFFILE}"
fi

dconf update

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi


# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

# Check for setting in any of the DConf db directories
# If files contain ibus or distro, ignore them.
# The assignment assumes that individual filenames don't contain :
readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/desktop/screensaver\\]" "/etc/dconf/db/" \
                                | grep -v 'distro\|ibus\|local.d' | cut -d":" -f1)
DCONFFILE="/etc/dconf/db/local.d/00-security-settings"
DBDIR="/etc/dconf/db/local.d"

mkdir -p "${DBDIR}"

# Comment out the configurations in databases different from the target one
if [ "${#SETTINGSFILES[@]}" -ne 0 ]
then
    if grep -q "^\\s*lock-enabled\\s*=" "${SETTINGSFILES[@]}"
    then
        
        sed -Ei "s/(^\s*)lock-enabled(\s*=)/#\1lock-enabled\2/g" "${SETTINGSFILES[@]}"
    fi
fi


[ ! -z "${DCONFFILE}" ] && echo "" >> "${DCONFFILE}"
if ! grep -q "\\[org/gnome/desktop/screensaver\\]" "${DCONFFILE}"
then
    printf '%s\n' "[org/gnome/desktop/screensaver]" >> ${DCONFFILE}
fi

escaped_value="$(sed -e 's/\\/\\\\/g' <<< "true")"
if grep -q "^\\s*lock-enabled\\s*=" "${DCONFFILE}"
then
        sed -i "s/\\s*lock-enabled\\s*=\\s*.*/lock-enabled=${escaped_value}/g" "${DCONFFILE}"
    else
        sed -i "\\|\\[org/gnome/desktop/screensaver\\]|a\\lock-enabled=${escaped_value}" "${DCONFFILE}"
fi

dconf update
# Check for setting in any of the DConf db directories
LOCKFILES=$(grep -r "^/org/gnome/desktop/screensaver/lock-enabled$" "/etc/dconf/db/" \
            | grep -v 'distro\|ibus\|local.d' | grep ":" | cut -d":" -f1)
LOCKSFOLDER="/etc/dconf/db/local.d/locks"

mkdir -p "${LOCKSFOLDER}"

# Comment out the configurations in databases different from the target one
if [[ ! -z "${LOCKFILES}" ]]
then
    sed -i -E "s|^/org/gnome/desktop/screensaver/lock-enabled$|#&|" "${LOCKFILES[@]}"
fi

if ! grep -qr "^/org/gnome/desktop/screensaver/lock-enabled$" /etc/dconf/db/local.d/
then
    echo "/org/gnome/desktop/screensaver/lock-enabled" >> "/etc/dconf/db/local.d/locks/00-security-settings-lock"
fi

dconf update

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm; then

# Check for setting in any of the DConf db directories
LOCKFILES=$(grep -r "^/org/gnome/desktop/screensaver/lock-enabled$" "/etc/dconf/db/" \
            | grep -v 'distro\|ibus\|local.d' | grep ":" | cut -d":" -f1)
LOCKSFOLDER="/etc/dconf/db/local.d/locks"

mkdir -p "${LOCKSFOLDER}"

# Comment out the configurations in databases different from the target one
if [[ ! -z "${LOCKFILES}" ]]
then
    sed -i -E "s|^/org/gnome/desktop/screensaver/lock-enabled$|#&|" "${LOCKFILES[@]}"
fi

if ! grep -qr "^/org/gnome/desktop/screensaver/lock-enabled$" /etc/dconf/db/local.d/
then
    echo "/org/gnome/desktop/screensaver/lock-enabled" >> "/etc/dconf/db/local.d/locks/00-security-settings-lock"
fi

dconf update

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

# Check for setting in any of the DConf db directories
LOCKFILES=$(grep -r "^/org/gnome/desktop/screensaver/lock-delay$" "/etc/dconf/db/" \
            | grep -v 'distro\|ibus\|local.d' | grep ":" | cut -d":" -f1)
LOCKSFOLDER="/etc/dconf/db/local.d/locks"

mkdir -p "${LOCKSFOLDER}"

# Comment out the configurations in databases different from the target one
if [[ ! -z "${LOCKFILES}" ]]
then
    sed -i -E "s|^/org/gnome/desktop/screensaver/lock-delay$|#&|" "${LOCKFILES[@]}"
fi

if ! grep -qr "^/org/gnome/desktop/screensaver/lock-delay$" /etc/dconf/db/local.d/
then
    echo "/org/gnome/desktop/screensaver/lock-delay" >> "/etc/dconf/db/local.d/locks/00-security-settings-lock"
fi

dconf update

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

# Check for setting in any of the DConf db directories
LOCKFILES=$(grep -r "^/org/gnome/desktop/session/idle-delay$" "/etc/dconf/db/" \
            | grep -v 'distro\|ibus\|local.d' | grep ":" | cut -d":" -f1)
LOCKSFOLDER="/etc/dconf/db/local.d/locks"

mkdir -p "${LOCKSFOLDER}"

# Comment out the configurations in databases different from the target one
if [[ ! -z "${LOCKFILES}" ]]
then
    sed -i -E "s|^/org/gnome/desktop/session/idle-delay$|#&|" "${LOCKFILES[@]}"
fi

if ! grep -qr "^/org/gnome/desktop/session/idle-delay$" /etc/dconf/db/local.d/
then
    echo "/org/gnome/desktop/session/idle-delay" >> "/etc/dconf/db/local.d/locks/00-security-settings-lock"
fi

dconf update

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi




# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

# Check for setting in any of the DConf db directories
# If files contain ibus or distro, ignore them.
# The assignment assumes that individual filenames don't contain :
readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/settings-daemon/plugins/media-keys\\]" "/etc/dconf/db/" \
                                | grep -v 'distro\|ibus\|local.d' | cut -d":" -f1)
DCONFFILE="/etc/dconf/db/local.d/00-security-settings"
DBDIR="/etc/dconf/db/local.d"

mkdir -p "${DBDIR}"

# Comment out the configurations in databases different from the target one
if [ "${#SETTINGSFILES[@]}" -ne 0 ]
then
    if grep -q "^\\s*logout\\s*=" "${SETTINGSFILES[@]}"
    then
        
        sed -Ei "s/(^\s*)logout(\s*=)/#\1logout\2/g" "${SETTINGSFILES[@]}"
    fi
fi


[ ! -z "${DCONFFILE}" ] && echo "" >> "${DCONFFILE}"
if ! grep -q "\\[org/gnome/settings-daemon/plugins/media-keys\\]" "${DCONFFILE}"
then
    printf '%s\n' "[org/gnome/settings-daemon/plugins/media-keys]" >> ${DCONFFILE}
fi

escaped_value="$(sed -e 's/\\/\\\\/g' <<< "''")"
if grep -q "^\\s*logout\\s*=" "${DCONFFILE}"
then
        sed -i "s/\\s*logout\\s*=\\s*.*/logout=${escaped_value}/g" "${DCONFFILE}"
    else
        sed -i "\\|\\[org/gnome/settings-daemon/plugins/media-keys\\]|a\\logout=${escaped_value}" "${DCONFFILE}"
fi

dconf update
# Check for setting in any of the DConf db directories
LOCKFILES=$(grep -r "^/org/gnome/settings-daemon/plugins/media-keys/logout$" "/etc/dconf/db/" \
            | grep -v 'distro\|ibus\|local.d' | grep ":" | cut -d":" -f1)
LOCKSFOLDER="/etc/dconf/db/local.d/locks"

mkdir -p "${LOCKSFOLDER}"

# Comment out the configurations in databases different from the target one
if [[ ! -z "${LOCKFILES}" ]]
then
    sed -i -E "s|^/org/gnome/settings-daemon/plugins/media-keys/logout$|#&|" "${LOCKFILES[@]}"
fi

if ! grep -qr "^/org/gnome/settings-daemon/plugins/media-keys/logout$" /etc/dconf/db/local.d/
then
    echo "/org/gnome/settings-daemon/plugins/media-keys/logout" >> "/etc/dconf/db/local.d/locks/00-security-settings-lock"
fi

dconf update

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

dconf update

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



for f in /etc/sudoers /etc/sudoers.d/* ; do
  if [ ! -e "$f" ] ; then
    continue
  fi
  matching_list=$(grep -P '^(?!#).*[\s]+\!authenticate.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      # comment out "!authenticate" matches to preserve user data
      sed -i "s/^${entry}$/# &/g" $f
    done <<< "$matching_list"

    /usr/sbin/visudo -cf $f &> /dev/null || echo "Fail to validate $f with visudo"
  fi
done


for f in /etc/sudoers /etc/sudoers.d/* ; do
  if [ ! -e "$f" ] ; then
    continue
  fi
  matching_list=$(grep -P '^(?!#).*[\s]+NOPASSWD[\s]*\:.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      # comment out "NOPASSWD" matches to preserve user data
      sed -i "s/^${entry}$/# &/g" $f
    done <<< "$matching_list"

    /usr/sbin/visudo -cf $f &> /dev/null || echo "Fail to validate $f with visudo"
  fi
done



# Remediation is applicable only in certain platforms
if rpm --quiet -q sudo; then

var_sudo_timestamp_timeout='5'


if grep -Px '^[\s]*Defaults.*timestamp_timeout[\s]*=.*' /etc/sudoers.d/*; then
    find /etc/sudoers.d/ -type f -exec sed -Ei "/^[[:blank:]]*Defaults.*timestamp_timeout[[:blank:]]*=.*/d" {} \;
fi

if /usr/sbin/visudo -qcf /etc/sudoers; then
    cp /etc/sudoers /etc/sudoers.bak
    if ! grep -P '^[\s]*Defaults.*timestamp_timeout[\s]*=[\s]*[-]?\w+.*$' /etc/sudoers; then
        # sudoers file doesn't define Option timestamp_timeout
        echo "Defaults timestamp_timeout=${var_sudo_timestamp_timeout}" >> /etc/sudoers
    else
        # sudoers file defines Option timestamp_timeout, remediate if appropriate value is not set
        if ! grep -P "^[\s]*Defaults.*timestamp_timeout[\s]*=[\s]*${var_sudo_timestamp_timeout}.*$" /etc/sudoers; then
            
            sed -Ei "s/(^[[:blank:]]*Defaults.*timestamp_timeout[[:blank:]]*=)[[:blank:]]*[-]?\w+(.*$)/\1${var_sudo_timestamp_timeout}\2/" /etc/sudoers
        fi
    fi
    
    # Check validity of sudoers and cleanup bak
    if /usr/sbin/visudo -qcf /etc/sudoers; then
        rm -f /etc/sudoers.bak
    else
        echo "Fail to validate remediated /etc/sudoers, reverting to original file."
        mv /etc/sudoers.bak /etc/sudoers
        false
    fi
else
    echo "Skipping remediation, /etc/sudoers failed to validate"
    false
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi


sudoers_config_file="/etc/sudoers"
sudoers_config_dir="/etc/sudoers.d"
sudoers_includedir_count=$(grep -c "#includedir" "$sudoers_config_file")
if [ "$sudoers_includedir_count" -gt 1 ]; then
    sed -i "/#includedir/d" "$sudoers_config_file"
    echo "#includedir /etc/sudoers.d" >> "$sudoers_config_file"
elif [ "$sudoers_includedir_count" -eq 0 ]; then
    echo "#includedir /etc/sudoers.d" >> "$sudoers_config_file"
else
    if ! grep -q "^#includedir /etc/sudoers.d" "$sudoers_config_file"; then
        sed -i "s|^#includedir.*|#includedir /etc/sudoers.d|g" "$sudoers_config_file"
    fi
fi

sed -Ei "/^#include\s/d; /^@includedir\s/d" "$sudoers_config_file"

if grep -Pr "^[#@]include(dir)?\s" "$sudoers_config_dir" ; then
    sed -Ei "/^[#@]include(dir)?\s/d" "$sudoers_config_dir"/*
fi


if grep -x '^Defaults targetpw$' /etc/sudoers; then
    sed -i "/Defaults targetpw/d" /etc/sudoers \;
fi
if grep -x '^Defaults targetpw$' /etc/sudoers.d/*; then
    find /etc/sudoers.d/ -type f -exec sed -i "/Defaults targetpw/d" {} \;
fi
if grep -x '^Defaults rootpw$' /etc/sudoers; then
    sed -i "/Defaults rootpw/d" /etc/sudoers \;
fi
if grep -x '^Defaults rootpw$' /etc/sudoers.d/*; then
    find /etc/sudoers.d/ -type f -exec sed -i "/Defaults rootpw/d" {} \;
fi
if grep -x '^Defaults runaspw$' /etc/sudoers; then
    sed -i "/Defaults runaspw/d" /etc/sudoers \;
fi
if grep -x '^Defaults runaspw$' /etc/sudoers.d/*; then
    find /etc/sudoers.d/ -type f -exec sed -i "/Defaults runaspw/d" {} \;
fi

if [ -e "/etc/sudoers" ] ; then
    
    LC_ALL=C sed -i "/Defaults !targetpw/d" "/etc/sudoers"
else
    touch "/etc/sudoers"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/sudoers"

cp "/etc/sudoers" "/etc/sudoers.bak"
# Insert at the end of the file
printf '%s\n' "Defaults !targetpw" >> "/etc/sudoers"
# Clean up after ourselves.
rm "/etc/sudoers.bak"
if [ -e "/etc/sudoers" ] ; then
    
    LC_ALL=C sed -i "/Defaults !rootpw/d" "/etc/sudoers"
else
    touch "/etc/sudoers"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/sudoers"

cp "/etc/sudoers" "/etc/sudoers.bak"
# Insert at the end of the file
printf '%s\n' "Defaults !rootpw" >> "/etc/sudoers"
# Clean up after ourselves.
rm "/etc/sudoers.bak"
if [ -e "/etc/sudoers" ] ; then
    
    LC_ALL=C sed -i "/Defaults !runaspw/d" "/etc/sudoers"
else
    touch "/etc/sudoers"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/sudoers"

cp "/etc/sudoers" "/etc/sudoers.bak"
# Insert at the end of the file
printf '%s\n' "Defaults !runaspw" >> "/etc/sudoers"
# Clean up after ourselves.
rm "/etc/sudoers.bak"



# Remediation is applicable only in certain platforms
if rpm --quiet -q dnf; then

if grep --silent ^clean_requirements_on_remove /etc/dnf.conf ; then
        sed -i "s/^clean_requirements_on_remove.*/clean_requirements_on_remove=1/g" /etc/dnf.conf
else
        echo -e "\n# Set clean_requirements_on_remove to 1 per security requirements" >> /etc/dnf.conf
        echo "clean_requirements_on_remove=1" >> /etc/dnf.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if rpm --quiet -q dnf; then

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^gpgcheck")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "1"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^gpgcheck\\>" "/etc/dnf.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^gpgcheck\\>.*/$escaped_formatted_output/gi" "/etc/dnf.conf"
else
    if [[ -s "/etc/dnf.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/dnf.conf" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/dnf.conf"
    fi
    cce="CCE-26989-4"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/dnf.conf" >> "/etc/dnf.conf"
    printf '%s\n' "$formatted_output" >> "/etc/dnf.conf"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if rpm --quiet -q dnf; then

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^localpkg_gpgcheck")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "1"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^localpkg_gpgcheck\\>" "/etc/dnf.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^localpkg_gpgcheck\\>.*/$escaped_formatted_output/gi" "/etc/dnf.conf"
else
    if [[ -s "/etc/dnf.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/dnf.conf" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/dnf.conf"
    fi
    cce="CCE-80347-8"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/dnf.conf" >> "/etc/dnf.conf"
    printf '%s\n' "$formatted_output" >> "/etc/dnf.conf"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi


# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm; then

# Check for setting in any of the DConf db directories
# If files contain ibus or distro, ignore them.
# The assignment assumes that individual filenames don't contain :
readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/login-screen\\]" "/etc/dconf/db/" \
                                | grep -v 'distro\|ibus\|gdm.d' | cut -d":" -f1)
DCONFFILE="/etc/dconf/db/gdm.d/00-security-settings"
DBDIR="/etc/dconf/db/gdm.d"

mkdir -p "${DBDIR}"

# Comment out the configurations in databases different from the target one
if [ "${#SETTINGSFILES[@]}" -ne 0 ]
then
    if grep -q "^\\s*banner-message-enable\\s*=" "${SETTINGSFILES[@]}"
    then
        
        sed -Ei "s/(^\s*)banner-message-enable(\s*=)/#\1banner-message-enable\2/g" "${SETTINGSFILES[@]}"
    fi
fi


[ ! -z "${DCONFFILE}" ] && echo "" >> "${DCONFFILE}"
if ! grep -q "\\[org/gnome/login-screen\\]" "${DCONFFILE}"
then
    printf '%s\n' "[org/gnome/login-screen]" >> ${DCONFFILE}
fi

escaped_value="$(sed -e 's/\\/\\\\/g' <<< "true")"
if grep -q "^\\s*banner-message-enable\\s*=" "${DCONFFILE}"
then
        sed -i "s/\\s*banner-message-enable\\s*=\\s*.*/banner-message-enable=${escaped_value}/g" "${DCONFFILE}"
    else
        sed -i "\\|\\[org/gnome/login-screen\\]|a\\banner-message-enable=${escaped_value}" "${DCONFFILE}"
fi

dconf update
# Check for setting in any of the DConf db directories
LOCKFILES=$(grep -r "^/org/gnome/login-screen/banner-message-enable$" "/etc/dconf/db/" \
            | grep -v 'distro\|ibus\|gdm.d' | grep ":" | cut -d":" -f1)
LOCKSFOLDER="/etc/dconf/db/gdm.d/locks"

mkdir -p "${LOCKSFOLDER}"

# Comment out the configurations in databases different from the target one
if [[ ! -z "${LOCKFILES}" ]]
then
    sed -i -E "s|^/org/gnome/login-screen/banner-message-enable$|#&|" "${LOCKFILES[@]}"
fi

if ! grep -qr "^/org/gnome/login-screen/banner-message-enable$" /etc/dconf/db/gdm.d/
then
    echo "/org/gnome/login-screen/banner-message-enable" >> "/etc/dconf/db/gdm.d/locks/00-security-settings-lock"
fi

dconf update

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi


# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm; then

login_banner_text='^(You[\s\n]+are[\s\n]+accessing[\s\n]+a[\s\n]+U\.S\.[\s\n]+Government[\s\n]+\(USG\)[\s\n]+Information[\s\n]+System[\s\n]+\(IS\)[\s\n]+that[\s\n]+is[\s\n]+provided[\s\n]+for[\s\n]+USG\-authorized[\s\n]+use[\s\n]+only\.[\s\n]+By[\s\n]+using[\s\n]+this[\s\n]+IS[\s\n]+\(which[\s\n]+includes[\s\n]+any[\s\n]+device[\s\n]+attached[\s\n]+to[\s\n]+this[\s\n]+IS\),[\s\n]+you[\s\n]+consent[\s\n]+to[\s\n]+the[\s\n]+following[\s\n]+conditions\:(?:[\n]+|(?:\\n)+)\-The[\s\n]+USG[\s\n]+routinely[\s\n]+intercepts[\s\n]+and[\s\n]+monitors[\s\n]+communications[\s\n]+on[\s\n]+this[\s\n]+IS[\s\n]+for[\s\n]+purposes[\s\n]+including,[\s\n]+but[\s\n]+not[\s\n]+limited[\s\n]+to,[\s\n]+penetration[\s\n]+testing,[\s\n]+COMSEC[\s\n]+monitoring,[\s\n]+network[\s\n]+operations[\s\n]+and[\s\n]+defense,[\s\n]+personnel[\s\n]+misconduct[\s\n]+\(PM\),[\s\n]+law[\s\n]+enforcement[\s\n]+\(LE\),[\s\n]+and[\s\n]+counterintelligence[\s\n]+\(CI\)[\s\n]+investigations\.(?:[\n]+|(?:\\n)+)\-At[\s\n]+any[\s\n]+time,[\s\n]+the[\s\n]+USG[\s\n]+may[\s\n]+inspect[\s\n]+and[\s\n]+seize[\s\n]+data[\s\n]+stored[\s\n]+on[\s\n]+this[\s\n]+IS\.(?:[\n]+|(?:\\n)+)\-Communications[\s\n]+using,[\s\n]+or[\s\n]+data[\s\n]+stored[\s\n]+on,[\s\n]+this[\s\n]+IS[\s\n]+are[\s\n]+not[\s\n]+private,[\s\n]+are[\s\n]+subject[\s\n]+to[\s\n]+routine[\s\n]+monitoring,[\s\n]+interception,[\s\n]+and[\s\n]+search,[\s\n]+and[\s\n]+may[\s\n]+be[\s\n]+disclosed[\s\n]+or[\s\n]+used[\s\n]+for[\s\n]+any[\s\n]+USG\-authorized[\s\n]+purpose\.(?:[\n]+|(?:\\n)+)\-This[\s\n]+IS[\s\n]+includes[\s\n]+security[\s\n]+measures[\s\n]+\(e\.g\.,[\s\n]+authentication[\s\n]+and[\s\n]+access[\s\n]+controls\)[\s\n]+to[\s\n]+protect[\s\n]+USG[\s\n]+interests\-\-not[\s\n]+for[\s\n]+your[\s\n]+personal[\s\n]+benefit[\s\n]+or[\s\n]+privacy\.(?:[\n]+|(?:\\n)+)\-Notwithstanding[\s\n]+the[\s\n]+above,[\s\n]+using[\s\n]+this[\s\n]+IS[\s\n]+does[\s\n]+not[\s\n]+constitute[\s\n]+consent[\s\n]+to[\s\n]+PM,[\s\n]+LE[\s\n]+or[\s\n]+CI[\s\n]+investigative[\s\n]+searching[\s\n]+or[\s\n]+monitoring[\s\n]+of[\s\n]+the[\s\n]+content[\s\n]+of[\s\n]+privileged[\s\n]+communications,[\s\n]+or[\s\n]+work[\s\n]+product,[\s\n]+related[\s\n]+to[\s\n]+personal[\s\n]+representation[\s\n]+or[\s\n]+services[\s\n]+by[\s\n]+attorneys,[\s\n]+psychotherapists,[\s\n]+or[\s\n]+clergy,[\s\n]+and[\s\n]+their[\s\n]+assistants\.[\s\n]+Such[\s\n]+communications[\s\n]+and[\s\n]+work[\s\n]+product[\s\n]+are[\s\n]+private[\s\n]+and[\s\n]+confidential\.[\s\n]+See[\s\n]+User[\s\n]+Agreement[\s\n]+for[\s\n]+details\.|I've[\s\n]+read[\s\n]+\&[\s\n]+consent[\s\n]+to[\s\n]+terms[\s\n]+in[\s\n]+IS[\s\n]+user[\s\n]+agreem't\.)$'


# Multiple regexes transform the banner regex into a usable banner
# 0 - Remove anchors around the banner text
login_banner_text=$(echo "$login_banner_text" | sed 's/^\^\(.*\)\$$/\1/g')
# 1 - Keep only the first banners if there are multiple
#    (dod_banners contains the long and short banner)
login_banner_text=$(echo "$login_banner_text" | sed 's/^(\(.*\.\)|.*)$/\1/g')
# 2 - Add spaces ' '. (Transforms regex for "space or newline" into a " ")
login_banner_text=$(echo "$login_banner_text" | sed 's/\[\\s\\n\]+/ /g')
# 3 - Adds newline "tokens". (Transforms "(?:\[\\n\]+|(?:\\n)+)" into "(n)*")
login_banner_text=$(echo "$login_banner_text" | sed 's/(?:\[\\n\]+|(?:\\\\n)+)/(n)*/g')
# 4 - Remove any leftover backslash. (From any parethesis in the banner, for example).
login_banner_text=$(echo "$login_banner_text" | sed 's/\\//g')
# 5 - Removes the newline "token." (Transforms them into newline escape sequences "\n").
#    ( Needs to be done after 4, otherwise the escapce sequence will become just "n".
login_banner_text=$(echo "$login_banner_text" | sed 's/(n)\*/\\n/g')

# Check for setting in any of the DConf db directories
# If files contain ibus or distro, ignore them.
# The assignment assumes that individual filenames don't contain :
readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/login-screen\\]" "/etc/dconf/db/" \
                                | grep -v 'distro\|ibus\|gdm.d' | cut -d":" -f1)
DCONFFILE="/etc/dconf/db/gdm.d/00-security-settings"
DBDIR="/etc/dconf/db/gdm.d"

mkdir -p "${DBDIR}"

# Comment out the configurations in databases different from the target one
if [ "${#SETTINGSFILES[@]}" -ne 0 ]
then
    if grep -q "^\\s*banner-message-text\\s*=" "${SETTINGSFILES[@]}"
    then
        
        sed -Ei "s/(^\s*)banner-message-text(\s*=)/#\1banner-message-text\2/g" "${SETTINGSFILES[@]}"
    fi
fi


[ ! -z "${DCONFFILE}" ] && echo "" >> "${DCONFFILE}"
if ! grep -q "\\[org/gnome/login-screen\\]" "${DCONFFILE}"
then
    printf '%s\n' "[org/gnome/login-screen]" >> ${DCONFFILE}
fi

escaped_value="$(sed -e 's/\\/\\\\/g' <<< "'${login_banner_text}'")"
if grep -q "^\\s*banner-message-text\\s*=" "${DCONFFILE}"
then
        sed -i "s/\\s*banner-message-text\\s*=\\s*.*/banner-message-text=${escaped_value}/g" "${DCONFFILE}"
    else
        sed -i "\\|\\[org/gnome/login-screen\\]|a\\banner-message-text=${escaped_value}" "${DCONFFILE}"
fi

dconf update
# Check for setting in any of the DConf db directories
LOCKFILES=$(grep -r "^/org/gnome/login-screen/banner-message-text$" "/etc/dconf/db/" \
            | grep -v 'distro\|ibus\|gdm.d' | grep ":" | cut -d":" -f1)
LOCKSFOLDER="/etc/dconf/db/gdm.d/locks"

mkdir -p "${LOCKSFOLDER}"

# Comment out the configurations in databases different from the target one
if [[ ! -z "${LOCKFILES}" ]]
then
    sed -i -E "s|^/org/gnome/login-screen/banner-message-text$|#&|" "${LOCKFILES[@]}"
fi

if ! grep -qr "^/org/gnome/login-screen/banner-message-text$" /etc/dconf/db/gdm.d/
then
    echo "/org/gnome/login-screen/banner-message-text" >> "/etc/dconf/db/gdm.d/locks/00-security-settings-lock"
fi

dconf update

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_password_pam_remember='5'
var_password_pam_remember_control_flag='requisite'


var_password_pam_remember_control_flag="$(echo $var_password_pam_remember_control_flag | cut -d \, -f 1)"

if [ -f /usr/bin/authselect ]; then
    if authselect list-features minimal | grep -q with-pwhistory; then
        if ! authselect check; then
        echo "
        authselect integrity check failed. Remediation aborted!
        This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
        It is not recommended to manually edit the PAM files when authselect tool is available.
        In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
        exit 1
        fi
        authselect enable-feature with-pwhistory

        authselect apply-changes -b
    else
        
        if ! authselect check; then
        echo "
        authselect integrity check failed. Remediation aborted!
        This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
        It is not recommended to manually edit the PAM files when authselect tool is available.
        In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
        exit 1
        fi

        CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
        # If not already in use, a custom profile is created preserving the enabled features.
        if [[ ! $CURRENT_PROFILE == custom/* ]]; then
            ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
            authselect create-profile hardening -b $CURRENT_PROFILE
            CURRENT_PROFILE="custom/hardening"
            
            authselect apply-changes -b --backup=before-hardening-custom-profile
            authselect select $CURRENT_PROFILE
            for feature in $ENABLED_FEATURES; do
                authselect enable-feature $feature;
            done
            
            authselect apply-changes -b --backup=after-hardening-custom-profile
        fi
        PAM_FILE_NAME=$(basename "/etc/pam.d/password-auth")
        PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

        authselect apply-changes -b
        if ! grep -qP '^\s*password\s+'"$var_password_pam_remember_control_flag"'\s+pam_pwhistory.so\s*.*' "$PAM_FILE_PATH"; then
            # Line matching group + control + module was not found. Check group + module.
            if [ "$(grep -cP '^\s*password\s+.*\s+pam_pwhistory.so\s*' "$PAM_FILE_PATH")" -eq 1 ]; then
                # The control is updated only if one single line matches.
                sed -i -E --follow-symlinks 's/^(\s*password\s+).*(\bpam_pwhistory.so.*)/\1'"$var_password_pam_remember_control_flag"' \2/' "$PAM_FILE_PATH"
            else
                LAST_MATCH_LINE=$(grep -nP "^password.*requisite.*pam_pwquality\.so" "$PAM_FILE_PATH" | tail -n 1 | cut -d: -f 1)
                if [ ! -z $LAST_MATCH_LINE ]; then
                    sed -i --follow-symlinks $LAST_MATCH_LINE' a password     '"$var_password_pam_remember_control_flag"'    pam_pwhistory.so' "$PAM_FILE_PATH"
                else
                    echo 'password    '"$var_password_pam_remember_control_flag"'    pam_pwhistory.so' >> "$PAM_FILE_PATH"
                fi
            fi
        fi
    fi
else
    if ! grep -qP '^\s*password\s+'"$var_password_pam_remember_control_flag"'\s+pam_pwhistory.so\s*.*' "/etc/pam.d/password-auth"; then
        # Line matching group + control + module was not found. Check group + module.
        if [ "$(grep -cP '^\s*password\s+.*\s+pam_pwhistory.so\s*' "/etc/pam.d/password-auth")" -eq 1 ]; then
            # The control is updated only if one single line matches.
            sed -i -E --follow-symlinks 's/^(\s*password\s+).*(\bpam_pwhistory.so.*)/\1'"$var_password_pam_remember_control_flag"' \2/' "/etc/pam.d/password-auth"
        else
            LAST_MATCH_LINE=$(grep -nP "^password.*requisite.*pam_pwquality\.so" "/etc/pam.d/password-auth" | tail -n 1 | cut -d: -f 1)
            if [ ! -z $LAST_MATCH_LINE ]; then
                sed -i --follow-symlinks $LAST_MATCH_LINE' a password     '"$var_password_pam_remember_control_flag"'    pam_pwhistory.so' "/etc/pam.d/password-auth"
            else
                echo 'password    '"$var_password_pam_remember_control_flag"'    pam_pwhistory.so' >> "/etc/pam.d/password-auth"
            fi
        fi
    fi
fi

PWHISTORY_CONF="/etc/security/pwhistory.conf"
if [ -f $PWHISTORY_CONF ]; then
    regex="^\s*remember\s*="
    line="remember = $var_password_pam_remember"
    if ! grep -q $regex $PWHISTORY_CONF; then
        echo $line >> $PWHISTORY_CONF
    else
        sed -i --follow-symlinks 's|^\s*\(remember\s*=\s*\)\(\S\+\)|\1'"$var_password_pam_remember"'|g' $PWHISTORY_CONF
    fi
    if [ -e "/etc/pam.d/password-auth" ] ; then
        PAM_FILE_PATH="/etc/pam.d/password-auth"
        if [ -f /usr/bin/authselect ]; then
            
            if ! authselect check; then
            echo "
            authselect integrity check failed. Remediation aborted!
            This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
            It is not recommended to manually edit the PAM files when authselect tool is available.
            In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
            exit 1
            fi

            CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
            # If not already in use, a custom profile is created preserving the enabled features.
            if [[ ! $CURRENT_PROFILE == custom/* ]]; then
                ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
                authselect create-profile hardening -b $CURRENT_PROFILE
                CURRENT_PROFILE="custom/hardening"
                
                authselect apply-changes -b --backup=before-hardening-custom-profile
                authselect select $CURRENT_PROFILE
                for feature in $ENABLED_FEATURES; do
                    authselect enable-feature $feature;
                done
                
                authselect apply-changes -b --backup=after-hardening-custom-profile
            fi
            PAM_FILE_NAME=$(basename "/etc/pam.d/password-auth")
            PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

            authselect apply-changes -b
        fi
        
    if grep -qP '^\s*password\s.*\bpam_pwhistory.so\s.*\bremember\b' "$PAM_FILE_PATH"; then
        sed -i -E --follow-symlinks 's/(.*password.*pam_pwhistory.so.*)\bremember\b=?[[:alnum:]]*(.*)/\1\2/g' "$PAM_FILE_PATH"
    fi
        if [ -f /usr/bin/authselect ]; then
            
            authselect apply-changes -b
        fi
    else
        echo "/etc/pam.d/password-auth was not found" >&2
    fi
else
    PAM_FILE_PATH="/etc/pam.d/password-auth"
    if [ -f /usr/bin/authselect ]; then
        
        if ! authselect check; then
        echo "
        authselect integrity check failed. Remediation aborted!
        This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
        It is not recommended to manually edit the PAM files when authselect tool is available.
        In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
        exit 1
        fi

        CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
        # If not already in use, a custom profile is created preserving the enabled features.
        if [[ ! $CURRENT_PROFILE == custom/* ]]; then
            ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
            authselect create-profile hardening -b $CURRENT_PROFILE
            CURRENT_PROFILE="custom/hardening"
            
            authselect apply-changes -b --backup=before-hardening-custom-profile
            authselect select $CURRENT_PROFILE
            for feature in $ENABLED_FEATURES; do
                authselect enable-feature $feature;
            done
            
            authselect apply-changes -b --backup=after-hardening-custom-profile
        fi
        PAM_FILE_NAME=$(basename "/etc/pam.d/password-auth")
        PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

        authselect apply-changes -b
    fi
    if ! grep -qP '^\s*password\s+'"requisite"'\s+pam_pwhistory.so\s*.*' "$PAM_FILE_PATH"; then
        # Line matching group + control + module was not found. Check group + module.
        if [ "$(grep -cP '^\s*password\s+.*\s+pam_pwhistory.so\s*' "$PAM_FILE_PATH")" -eq 1 ]; then
            # The control is updated only if one single line matches.
            sed -i -E --follow-symlinks 's/^(\s*password\s+).*(\bpam_pwhistory.so.*)/\1'"requisite"' \2/' "$PAM_FILE_PATH"
        else
            echo 'password    '"requisite"'    pam_pwhistory.so' >> "$PAM_FILE_PATH"
        fi
    fi
    # Check the option
    if ! grep -qP '^\s*password\s+'"requisite"'\s+pam_pwhistory.so\s*.*\sremember\b' "$PAM_FILE_PATH"; then
        sed -i -E --follow-symlinks '/\s*password\s+'"requisite"'\s+pam_pwhistory.so.*/ s/$/ remember='"$var_password_pam_remember"'/' "$PAM_FILE_PATH"
    else
        sed -i -E --follow-symlinks 's/(\s*password\s+'"requisite"'\s+pam_pwhistory.so\s+.*)('"remember"'=)[[:alnum:]]+\s*(.*)/\1\2'"$var_password_pam_remember"' \3/' "$PAM_FILE_PATH"
    fi
    if [ -f /usr/bin/authselect ]; then
        
        authselect apply-changes -b
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_password_pam_remember='5'
var_password_pam_remember_control_flag='requisite'


var_password_pam_remember_control_flag="$(echo $var_password_pam_remember_control_flag | cut -d \, -f 1)"

if [ -f /usr/bin/authselect ]; then
    if authselect list-features minimal | grep -q with-pwhistory; then
        if ! authselect check; then
        echo "
        authselect integrity check failed. Remediation aborted!
        This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
        It is not recommended to manually edit the PAM files when authselect tool is available.
        In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
        exit 1
        fi
        authselect enable-feature with-pwhistory

        authselect apply-changes -b
    else
        
        if ! authselect check; then
        echo "
        authselect integrity check failed. Remediation aborted!
        This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
        It is not recommended to manually edit the PAM files when authselect tool is available.
        In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
        exit 1
        fi

        CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
        # If not already in use, a custom profile is created preserving the enabled features.
        if [[ ! $CURRENT_PROFILE == custom/* ]]; then
            ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
            authselect create-profile hardening -b $CURRENT_PROFILE
            CURRENT_PROFILE="custom/hardening"
            
            authselect apply-changes -b --backup=before-hardening-custom-profile
            authselect select $CURRENT_PROFILE
            for feature in $ENABLED_FEATURES; do
                authselect enable-feature $feature;
            done
            
            authselect apply-changes -b --backup=after-hardening-custom-profile
        fi
        PAM_FILE_NAME=$(basename "/etc/pam.d/system-auth")
        PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

        authselect apply-changes -b
        if ! grep -qP '^\s*password\s+'"$var_password_pam_remember_control_flag"'\s+pam_pwhistory.so\s*.*' "$PAM_FILE_PATH"; then
            # Line matching group + control + module was not found. Check group + module.
            if [ "$(grep -cP '^\s*password\s+.*\s+pam_pwhistory.so\s*' "$PAM_FILE_PATH")" -eq 1 ]; then
                # The control is updated only if one single line matches.
                sed -i -E --follow-symlinks 's/^(\s*password\s+).*(\bpam_pwhistory.so.*)/\1'"$var_password_pam_remember_control_flag"' \2/' "$PAM_FILE_PATH"
            else
                LAST_MATCH_LINE=$(grep -nP "^password.*requisite.*pam_pwquality\.so" "$PAM_FILE_PATH" | tail -n 1 | cut -d: -f 1)
                if [ ! -z $LAST_MATCH_LINE ]; then
                    sed -i --follow-symlinks $LAST_MATCH_LINE' a password     '"$var_password_pam_remember_control_flag"'    pam_pwhistory.so' "$PAM_FILE_PATH"
                else
                    echo 'password    '"$var_password_pam_remember_control_flag"'    pam_pwhistory.so' >> "$PAM_FILE_PATH"
                fi
            fi
        fi
    fi
else
    if ! grep -qP '^\s*password\s+'"$var_password_pam_remember_control_flag"'\s+pam_pwhistory.so\s*.*' "/etc/pam.d/system-auth"; then
        # Line matching group + control + module was not found. Check group + module.
        if [ "$(grep -cP '^\s*password\s+.*\s+pam_pwhistory.so\s*' "/etc/pam.d/system-auth")" -eq 1 ]; then
            # The control is updated only if one single line matches.
            sed -i -E --follow-symlinks 's/^(\s*password\s+).*(\bpam_pwhistory.so.*)/\1'"$var_password_pam_remember_control_flag"' \2/' "/etc/pam.d/system-auth"
        else
            LAST_MATCH_LINE=$(grep -nP "^password.*requisite.*pam_pwquality\.so" "/etc/pam.d/system-auth" | tail -n 1 | cut -d: -f 1)
            if [ ! -z $LAST_MATCH_LINE ]; then
                sed -i --follow-symlinks $LAST_MATCH_LINE' a password     '"$var_password_pam_remember_control_flag"'    pam_pwhistory.so' "/etc/pam.d/system-auth"
            else
                echo 'password    '"$var_password_pam_remember_control_flag"'    pam_pwhistory.so' >> "/etc/pam.d/system-auth"
            fi
        fi
    fi
fi

PWHISTORY_CONF="/etc/security/pwhistory.conf"
if [ -f $PWHISTORY_CONF ]; then
    regex="^\s*remember\s*="
    line="remember = $var_password_pam_remember"
    if ! grep -q $regex $PWHISTORY_CONF; then
        echo $line >> $PWHISTORY_CONF
    else
        sed -i --follow-symlinks 's|^\s*\(remember\s*=\s*\)\(\S\+\)|\1'"$var_password_pam_remember"'|g' $PWHISTORY_CONF
    fi
    if [ -e "/etc/pam.d/system-auth" ] ; then
        PAM_FILE_PATH="/etc/pam.d/system-auth"
        if [ -f /usr/bin/authselect ]; then
            
            if ! authselect check; then
            echo "
            authselect integrity check failed. Remediation aborted!
            This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
            It is not recommended to manually edit the PAM files when authselect tool is available.
            In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
            exit 1
            fi

            CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
            # If not already in use, a custom profile is created preserving the enabled features.
            if [[ ! $CURRENT_PROFILE == custom/* ]]; then
                ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
                authselect create-profile hardening -b $CURRENT_PROFILE
                CURRENT_PROFILE="custom/hardening"
                
                authselect apply-changes -b --backup=before-hardening-custom-profile
                authselect select $CURRENT_PROFILE
                for feature in $ENABLED_FEATURES; do
                    authselect enable-feature $feature;
                done
                
                authselect apply-changes -b --backup=after-hardening-custom-profile
            fi
            PAM_FILE_NAME=$(basename "/etc/pam.d/system-auth")
            PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

            authselect apply-changes -b
        fi
        
    if grep -qP '^\s*password\s.*\bpam_pwhistory.so\s.*\bremember\b' "$PAM_FILE_PATH"; then
        sed -i -E --follow-symlinks 's/(.*password.*pam_pwhistory.so.*)\bremember\b=?[[:alnum:]]*(.*)/\1\2/g' "$PAM_FILE_PATH"
    fi
        if [ -f /usr/bin/authselect ]; then
            
            authselect apply-changes -b
        fi
    else
        echo "/etc/pam.d/system-auth was not found" >&2
    fi
else
    PAM_FILE_PATH="/etc/pam.d/system-auth"
    if [ -f /usr/bin/authselect ]; then
        
        if ! authselect check; then
        echo "
        authselect integrity check failed. Remediation aborted!
        This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
        It is not recommended to manually edit the PAM files when authselect tool is available.
        In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
        exit 1
        fi

        CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
        # If not already in use, a custom profile is created preserving the enabled features.
        if [[ ! $CURRENT_PROFILE == custom/* ]]; then
            ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
            authselect create-profile hardening -b $CURRENT_PROFILE
            CURRENT_PROFILE="custom/hardening"
            
            authselect apply-changes -b --backup=before-hardening-custom-profile
            authselect select $CURRENT_PROFILE
            for feature in $ENABLED_FEATURES; do
                authselect enable-feature $feature;
            done
            
            authselect apply-changes -b --backup=after-hardening-custom-profile
        fi
        PAM_FILE_NAME=$(basename "/etc/pam.d/system-auth")
        PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

        authselect apply-changes -b
    fi
    if ! grep -qP '^\s*password\s+'"requisite"'\s+pam_pwhistory.so\s*.*' "$PAM_FILE_PATH"; then
        # Line matching group + control + module was not found. Check group + module.
        if [ "$(grep -cP '^\s*password\s+.*\s+pam_pwhistory.so\s*' "$PAM_FILE_PATH")" -eq 1 ]; then
            # The control is updated only if one single line matches.
            sed -i -E --follow-symlinks 's/^(\s*password\s+).*(\bpam_pwhistory.so.*)/\1'"requisite"' \2/' "$PAM_FILE_PATH"
        else
            echo 'password    '"requisite"'    pam_pwhistory.so' >> "$PAM_FILE_PATH"
        fi
    fi
    # Check the option
    if ! grep -qP '^\s*password\s+'"requisite"'\s+pam_pwhistory.so\s*.*\sremember\b' "$PAM_FILE_PATH"; then
        sed -i -E --follow-symlinks '/\s*password\s+'"requisite"'\s+pam_pwhistory.so.*/ s/$/ remember='"$var_password_pam_remember"'/' "$PAM_FILE_PATH"
    else
        sed -i -E --follow-symlinks 's/(\s*password\s+'"requisite"'\s+pam_pwhistory.so\s+.*)('"remember"'=)[[:alnum:]]+\s*(.*)/\1\2'"$var_password_pam_remember"' \3/' "$PAM_FILE_PATH"
    fi
    if [ -f /usr/bin/authselect ]; then
        
        authselect apply-changes -b
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi


# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_accounts_passwords_pam_faillock_deny='3'


if [ -f /usr/bin/authselect ]; then
    if ! authselect check; then
echo "
authselect integrity check failed. Remediation aborted!
This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
It is not recommended to manually edit the PAM files when authselect tool is available.
In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
exit 1
fi
authselect enable-feature with-faillock

authselect apply-changes -b
else
    
AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
for pam_file in "${AUTH_FILES[@]}"
do
    if ! grep -qE '^\s*auth\s+required\s+pam_faillock\.so\s+(preauth silent|authfail).*$' "$pam_file" ; then
        sed -i --follow-symlinks '/^auth.*sufficient.*pam_unix\.so.*/i auth        required      pam_faillock.so preauth silent' "$pam_file"
        sed -i --follow-symlinks '/^auth.*required.*pam_deny\.so.*/i auth        required      pam_faillock.so authfail' "$pam_file"
        sed -i --follow-symlinks '/^account.*required.*pam_unix\.so.*/i account     required      pam_faillock.so' "$pam_file"
    fi
    sed -Ei 's/(auth.*)(\[default=die\])(.*pam_faillock\.so)/\1required     \3/g' "$pam_file"
done

fi

AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")

FAILLOCK_CONF="/etc/security/faillock.conf"
if [ -f $FAILLOCK_CONF ]; then
    regex="^\s*deny\s*="
    line="deny = $var_accounts_passwords_pam_faillock_deny"
    if ! grep -q $regex $FAILLOCK_CONF; then
        echo $line >> $FAILLOCK_CONF
    else
        sed -i --follow-symlinks 's|^\s*\(deny\s*=\s*\)\(\S\+\)|\1'"$var_accounts_passwords_pam_faillock_deny"'|g' $FAILLOCK_CONF
    fi
    for pam_file in "${AUTH_FILES[@]}"
    do
        if [ -e "$pam_file" ] ; then
            PAM_FILE_PATH="$pam_file"
            if [ -f /usr/bin/authselect ]; then
                
                if ! authselect check; then
                echo "
                authselect integrity check failed. Remediation aborted!
                This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
                It is not recommended to manually edit the PAM files when authselect tool is available.
                In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
                exit 1
                fi

                CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
                # If not already in use, a custom profile is created preserving the enabled features.
                if [[ ! $CURRENT_PROFILE == custom/* ]]; then
                    ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
                    authselect create-profile hardening -b $CURRENT_PROFILE
                    CURRENT_PROFILE="custom/hardening"
                    
                    authselect apply-changes -b --backup=before-hardening-custom-profile
                    authselect select $CURRENT_PROFILE
                    for feature in $ENABLED_FEATURES; do
                        authselect enable-feature $feature;
                    done
                    
                    authselect apply-changes -b --backup=after-hardening-custom-profile
                fi
                PAM_FILE_NAME=$(basename "$pam_file")
                PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

                authselect apply-changes -b
            fi
            
        if grep -qP '^\s*auth\s.*\bpam_faillock.so\s.*\bdeny\b' "$PAM_FILE_PATH"; then
            sed -i -E --follow-symlinks 's/(.*auth.*pam_faillock.so.*)\bdeny\b=?[[:alnum:]]*(.*)/\1\2/g' "$PAM_FILE_PATH"
        fi
            if [ -f /usr/bin/authselect ]; then
                
                authselect apply-changes -b
            fi
        else
            echo "$pam_file was not found" >&2
        fi
    done
else
    for pam_file in "${AUTH_FILES[@]}"
    do
        if ! grep -qE '^\s*auth.*pam_faillock\.so (preauth|authfail).*deny' "$pam_file"; then
            sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*preauth.*silent.*/ s/$/ deny='"$var_accounts_passwords_pam_faillock_deny"'/' "$pam_file"
            sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*authfail.*/ s/$/ deny='"$var_accounts_passwords_pam_faillock_deny"'/' "$pam_file"
        else
            sed -i --follow-symlinks 's/\(^auth.*required.*pam_faillock\.so.*preauth.*silent.*\)\('"deny"'=\)[0-9]\+\(.*\)/\1\2'"$var_accounts_passwords_pam_faillock_deny"'\3/' "$pam_file"
            sed -i --follow-symlinks 's/\(^auth.*required.*pam_faillock\.so.*authfail.*\)\('"deny"'=\)[0-9]\+\(.*\)/\1\2'"$var_accounts_passwords_pam_faillock_deny"'\3/' "$pam_file"
        fi
    done
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi


# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

if [ -f /usr/bin/authselect ]; then
    if ! authselect check; then
echo "
authselect integrity check failed. Remediation aborted!
This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
It is not recommended to manually edit the PAM files when authselect tool is available.
In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
exit 1
fi
authselect enable-feature with-faillock

authselect apply-changes -b
else
    
AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
for pam_file in "${AUTH_FILES[@]}"
do
    if ! grep -qE '^\s*auth\s+required\s+pam_faillock\.so\s+(preauth silent|authfail).*$' "$pam_file" ; then
        sed -i --follow-symlinks '/^auth.*sufficient.*pam_unix\.so.*/i auth        required      pam_faillock.so preauth silent' "$pam_file"
        sed -i --follow-symlinks '/^auth.*required.*pam_deny\.so.*/i auth        required      pam_faillock.so authfail' "$pam_file"
        sed -i --follow-symlinks '/^account.*required.*pam_unix\.so.*/i account     required      pam_faillock.so' "$pam_file"
    fi
    sed -Ei 's/(auth.*)(\[default=die\])(.*pam_faillock\.so)/\1required     \3/g' "$pam_file"
done

fi

AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")

FAILLOCK_CONF="/etc/security/faillock.conf"
if [ -f $FAILLOCK_CONF ]; then
    regex="^\s*even_deny_root"
    line="even_deny_root"
    if ! grep -q $regex $FAILLOCK_CONF; then
        echo $line >> $FAILLOCK_CONF
    fi
    for pam_file in "${AUTH_FILES[@]}"
    do
        if [ -e "$pam_file" ] ; then
            PAM_FILE_PATH="$pam_file"
            if [ -f /usr/bin/authselect ]; then
                
                if ! authselect check; then
                echo "
                authselect integrity check failed. Remediation aborted!
                This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
                It is not recommended to manually edit the PAM files when authselect tool is available.
                In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
                exit 1
                fi

                CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
                # If not already in use, a custom profile is created preserving the enabled features.
                if [[ ! $CURRENT_PROFILE == custom/* ]]; then
                    ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
                    authselect create-profile hardening -b $CURRENT_PROFILE
                    CURRENT_PROFILE="custom/hardening"
                    
                    authselect apply-changes -b --backup=before-hardening-custom-profile
                    authselect select $CURRENT_PROFILE
                    for feature in $ENABLED_FEATURES; do
                        authselect enable-feature $feature;
                    done
                    
                    authselect apply-changes -b --backup=after-hardening-custom-profile
                fi
                PAM_FILE_NAME=$(basename "$pam_file")
                PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

                authselect apply-changes -b
            fi
            
        if grep -qP '^\s*auth\s.*\bpam_faillock.so\s.*\beven_deny_root\b' "$PAM_FILE_PATH"; then
            sed -i -E --follow-symlinks 's/(.*auth.*pam_faillock.so.*)\beven_deny_root\b=?[[:alnum:]]*(.*)/\1\2/g' "$PAM_FILE_PATH"
        fi
            if [ -f /usr/bin/authselect ]; then
                
                authselect apply-changes -b
            fi
        else
            echo "$pam_file was not found" >&2
        fi
    done
else
    for pam_file in "${AUTH_FILES[@]}"
    do
        if ! grep -qE '^\s*auth.*pam_faillock\.so (preauth|authfail).*even_deny_root' "$pam_file"; then
            sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*preauth.*silent.*/ s/$/ even_deny_root/' "$pam_file"
            sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*authfail.*/ s/$/ even_deny_root/' "$pam_file"
        fi
    done
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi


# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_accounts_passwords_pam_faillock_fail_interval='900'


if [ -f /usr/bin/authselect ]; then
    if ! authselect check; then
echo "
authselect integrity check failed. Remediation aborted!
This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
It is not recommended to manually edit the PAM files when authselect tool is available.
In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
exit 1
fi
authselect enable-feature with-faillock

authselect apply-changes -b
else
    
AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
for pam_file in "${AUTH_FILES[@]}"
do
    if ! grep -qE '^\s*auth\s+required\s+pam_faillock\.so\s+(preauth silent|authfail).*$' "$pam_file" ; then
        sed -i --follow-symlinks '/^auth.*sufficient.*pam_unix\.so.*/i auth        required      pam_faillock.so preauth silent' "$pam_file"
        sed -i --follow-symlinks '/^auth.*required.*pam_deny\.so.*/i auth        required      pam_faillock.so authfail' "$pam_file"
        sed -i --follow-symlinks '/^account.*required.*pam_unix\.so.*/i account     required      pam_faillock.so' "$pam_file"
    fi
    sed -Ei 's/(auth.*)(\[default=die\])(.*pam_faillock\.so)/\1required     \3/g' "$pam_file"
done

fi

AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")

FAILLOCK_CONF="/etc/security/faillock.conf"
if [ -f $FAILLOCK_CONF ]; then
    regex="^\s*fail_interval\s*="
    line="fail_interval = $var_accounts_passwords_pam_faillock_fail_interval"
    if ! grep -q $regex $FAILLOCK_CONF; then
        echo $line >> $FAILLOCK_CONF
    else
        sed -i --follow-symlinks 's|^\s*\(fail_interval\s*=\s*\)\(\S\+\)|\1'"$var_accounts_passwords_pam_faillock_fail_interval"'|g' $FAILLOCK_CONF
    fi
    for pam_file in "${AUTH_FILES[@]}"
    do
        if [ -e "$pam_file" ] ; then
            PAM_FILE_PATH="$pam_file"
            if [ -f /usr/bin/authselect ]; then
                
                if ! authselect check; then
                echo "
                authselect integrity check failed. Remediation aborted!
                This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
                It is not recommended to manually edit the PAM files when authselect tool is available.
                In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
                exit 1
                fi

                CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
                # If not already in use, a custom profile is created preserving the enabled features.
                if [[ ! $CURRENT_PROFILE == custom/* ]]; then
                    ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
                    authselect create-profile hardening -b $CURRENT_PROFILE
                    CURRENT_PROFILE="custom/hardening"
                    
                    authselect apply-changes -b --backup=before-hardening-custom-profile
                    authselect select $CURRENT_PROFILE
                    for feature in $ENABLED_FEATURES; do
                        authselect enable-feature $feature;
                    done
                    
                    authselect apply-changes -b --backup=after-hardening-custom-profile
                fi
                PAM_FILE_NAME=$(basename "$pam_file")
                PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

                authselect apply-changes -b
            fi
            
        if grep -qP '^\s*auth\s.*\bpam_faillock.so\s.*\bfail_interval\b' "$PAM_FILE_PATH"; then
            sed -i -E --follow-symlinks 's/(.*auth.*pam_faillock.so.*)\bfail_interval\b=?[[:alnum:]]*(.*)/\1\2/g' "$PAM_FILE_PATH"
        fi
            if [ -f /usr/bin/authselect ]; then
                
                authselect apply-changes -b
            fi
        else
            echo "$pam_file was not found" >&2
        fi
    done
else
    for pam_file in "${AUTH_FILES[@]}"
    do
        if ! grep -qE '^\s*auth.*pam_faillock\.so (preauth|authfail).*fail_interval' "$pam_file"; then
            sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*preauth.*silent.*/ s/$/ fail_interval='"$var_accounts_passwords_pam_faillock_fail_interval"'/' "$pam_file"
            sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*authfail.*/ s/$/ fail_interval='"$var_accounts_passwords_pam_faillock_fail_interval"'/' "$pam_file"
        else
            sed -i --follow-symlinks 's/\(^auth.*required.*pam_faillock\.so.*preauth.*silent.*\)\('"fail_interval"'=\)[0-9]\+\(.*\)/\1\2'"$var_accounts_passwords_pam_faillock_fail_interval"'\3/' "$pam_file"
            sed -i --follow-symlinks 's/\(^auth.*required.*pam_faillock\.so.*authfail.*\)\('"fail_interval"'=\)[0-9]\+\(.*\)/\1\2'"$var_accounts_passwords_pam_faillock_fail_interval"'\3/' "$pam_file"
        fi
    done
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi


# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_accounts_passwords_pam_faillock_unlock_time='0'


if [ -f /usr/bin/authselect ]; then
    if ! authselect check; then
echo "
authselect integrity check failed. Remediation aborted!
This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
It is not recommended to manually edit the PAM files when authselect tool is available.
In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
exit 1
fi
authselect enable-feature with-faillock

authselect apply-changes -b
else
    
AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
for pam_file in "${AUTH_FILES[@]}"
do
    if ! grep -qE '^\s*auth\s+required\s+pam_faillock\.so\s+(preauth silent|authfail).*$' "$pam_file" ; then
        sed -i --follow-symlinks '/^auth.*sufficient.*pam_unix\.so.*/i auth        required      pam_faillock.so preauth silent' "$pam_file"
        sed -i --follow-symlinks '/^auth.*required.*pam_deny\.so.*/i auth        required      pam_faillock.so authfail' "$pam_file"
        sed -i --follow-symlinks '/^account.*required.*pam_unix\.so.*/i account     required      pam_faillock.so' "$pam_file"
    fi
    sed -Ei 's/(auth.*)(\[default=die\])(.*pam_faillock\.so)/\1required     \3/g' "$pam_file"
done

fi

AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")

FAILLOCK_CONF="/etc/security/faillock.conf"
if [ -f $FAILLOCK_CONF ]; then
    regex="^\s*unlock_time\s*="
    line="unlock_time = $var_accounts_passwords_pam_faillock_unlock_time"
    if ! grep -q $regex $FAILLOCK_CONF; then
        echo $line >> $FAILLOCK_CONF
    else
        sed -i --follow-symlinks 's|^\s*\(unlock_time\s*=\s*\)\(\S\+\)|\1'"$var_accounts_passwords_pam_faillock_unlock_time"'|g' $FAILLOCK_CONF
    fi
    for pam_file in "${AUTH_FILES[@]}"
    do
        if [ -e "$pam_file" ] ; then
            PAM_FILE_PATH="$pam_file"
            if [ -f /usr/bin/authselect ]; then
                
                if ! authselect check; then
                echo "
                authselect integrity check failed. Remediation aborted!
                This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
                It is not recommended to manually edit the PAM files when authselect tool is available.
                In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
                exit 1
                fi

                CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
                # If not already in use, a custom profile is created preserving the enabled features.
                if [[ ! $CURRENT_PROFILE == custom/* ]]; then
                    ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
                    authselect create-profile hardening -b $CURRENT_PROFILE
                    CURRENT_PROFILE="custom/hardening"
                    
                    authselect apply-changes -b --backup=before-hardening-custom-profile
                    authselect select $CURRENT_PROFILE
                    for feature in $ENABLED_FEATURES; do
                        authselect enable-feature $feature;
                    done
                    
                    authselect apply-changes -b --backup=after-hardening-custom-profile
                fi
                PAM_FILE_NAME=$(basename "$pam_file")
                PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

                authselect apply-changes -b
            fi
            
        if grep -qP '^\s*auth\s.*\bpam_faillock.so\s.*\bunlock_time\b' "$PAM_FILE_PATH"; then
            sed -i -E --follow-symlinks 's/(.*auth.*pam_faillock.so.*)\bunlock_time\b=?[[:alnum:]]*(.*)/\1\2/g' "$PAM_FILE_PATH"
        fi
            if [ -f /usr/bin/authselect ]; then
                
                authselect apply-changes -b
            fi
        else
            echo "$pam_file was not found" >&2
        fi
    done
else
    for pam_file in "${AUTH_FILES[@]}"
    do
        if ! grep -qE '^\s*auth.*pam_faillock\.so (preauth|authfail).*unlock_time' "$pam_file"; then
            sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*preauth.*silent.*/ s/$/ unlock_time='"$var_accounts_passwords_pam_faillock_unlock_time"'/' "$pam_file"
            sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*authfail.*/ s/$/ unlock_time='"$var_accounts_passwords_pam_faillock_unlock_time"'/' "$pam_file"
        else
            sed -i --follow-symlinks 's/\(^auth.*required.*pam_faillock\.so.*preauth.*silent.*\)\('"unlock_time"'=\)[0-9]\+\(.*\)/\1\2'"$var_accounts_passwords_pam_faillock_unlock_time"'\3/' "$pam_file"
            sed -i --follow-symlinks 's/\(^auth.*required.*pam_faillock\.so.*authfail.*\)\('"unlock_time"'=\)[0-9]\+\(.*\)/\1\2'"$var_accounts_passwords_pam_faillock_unlock_time"'\3/' "$pam_file"
        fi
    done
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi


# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_password_pam_dcredit='-1'






# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^dcredit")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_dcredit"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^dcredit\\>" "/etc/security/pwquality.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^dcredit\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
else
    if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
    fi
    cce="CCE-27214-6"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/security/pwquality.conf" >> "/etc/security/pwquality.conf"
    printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_password_pam_difok='8'






# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^difok")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_difok"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^difok\\>" "/etc/security/pwquality.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^difok\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
else
    if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
    fi
    cce="CCE-82020-9"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/security/pwquality.conf" >> "/etc/security/pwquality.conf"
    printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_password_pam_lcredit='-1'






# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^lcredit")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_lcredit"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^lcredit\\>" "/etc/security/pwquality.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^lcredit\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
else
    if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
    fi
    cce="CCE-27345-8"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/security/pwquality.conf" >> "/etc/security/pwquality.conf"
    printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi


# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_password_pam_maxclassrepeat='4'






# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^maxclassrepeat")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_maxclassrepeat"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^maxclassrepeat\\>" "/etc/security/pwquality.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^maxclassrepeat\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
else
    if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
    fi
    cce="CCE-27512-3"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/security/pwquality.conf" >> "/etc/security/pwquality.conf"
    printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi


# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_password_pam_maxrepeat='3'






# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^maxrepeat")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_maxrepeat"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^maxrepeat\\>" "/etc/security/pwquality.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^maxrepeat\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
else
    if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
    fi
    cce="CCE-82055-5"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/security/pwquality.conf" >> "/etc/security/pwquality.conf"
    printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_password_pam_minclass='4'






# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^minclass")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_minclass"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^minclass\\>" "/etc/security/pwquality.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^minclass\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
else
    if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
    fi
    cce="CCE-82045-6"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/security/pwquality.conf" >> "/etc/security/pwquality.conf"
    printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi


# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_password_pam_minlen='15'






# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^minlen")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_minlen"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^minlen\\>" "/etc/security/pwquality.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^minlen\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
else
    if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
    fi
    cce="CCE-27293-0"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/security/pwquality.conf" >> "/etc/security/pwquality.conf"
    printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi





# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_password_pam_ocredit='-1'






# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^ocredit")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_ocredit"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^ocredit\\>" "/etc/security/pwquality.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^ocredit\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
else
    if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
    fi
    cce="CCE-27360-7"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/security/pwquality.conf" >> "/etc/security/pwquality.conf"
    printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi





# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_password_pam_retry='3'



	
		if [ -e "/etc/pam.d/system-auth" ] ; then
    PAM_FILE_PATH="/etc/pam.d/system-auth"
    if [ -f /usr/bin/authselect ]; then
        
        if ! authselect check; then
        echo "
        authselect integrity check failed. Remediation aborted!
        This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
        It is not recommended to manually edit the PAM files when authselect tool is available.
        In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
        exit 1
        fi

        CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
        # If not already in use, a custom profile is created preserving the enabled features.
        if [[ ! $CURRENT_PROFILE == custom/* ]]; then
            ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
            authselect create-profile hardening -b $CURRENT_PROFILE
            CURRENT_PROFILE="custom/hardening"
            
            authselect apply-changes -b --backup=before-hardening-custom-profile
            authselect select $CURRENT_PROFILE
            for feature in $ENABLED_FEATURES; do
                authselect enable-feature $feature;
            done
            
            authselect apply-changes -b --backup=after-hardening-custom-profile
        fi
        PAM_FILE_NAME=$(basename "/etc/pam.d/system-auth")
        PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

        authselect apply-changes -b
    fi
    if ! grep -qP '^\s*password\s+'"requisite"'\s+pam_pwquality.so\s*.*' "$PAM_FILE_PATH"; then
            # Line matching group + control + module was not found. Check group + module.
            if [ "$(grep -cP '^\s*password\s+.*\s+pam_pwquality.so\s*' "$PAM_FILE_PATH")" -eq 1 ]; then
                # The control is updated only if one single line matches.
                sed -i -E --follow-symlinks 's/^(\s*password\s+).*(\bpam_pwquality.so.*)/\1'"requisite"' \2/' "$PAM_FILE_PATH"
            else
                LAST_MATCH_LINE=$(grep -nP "^\s*account" "$PAM_FILE_PATH" | tail -n 1 | cut -d: -f 1)
                if [ ! -z $LAST_MATCH_LINE ]; then
                    sed -i --follow-symlinks $LAST_MATCH_LINE' a password     '"requisite"'    pam_pwquality.so' "$PAM_FILE_PATH"
                else
                    echo 'password    '"requisite"'    pam_pwquality.so' >> "$PAM_FILE_PATH"
                fi
            fi
        fi
        # Check the option
        if ! grep -qP '^\s*password\s+'"requisite"'\s+pam_pwquality.so\s*.*\sretry\b' "$PAM_FILE_PATH"; then
            sed -i -E --follow-symlinks '/\s*password\s+'"requisite"'\s+pam_pwquality.so.*/ s/$/ retry='"$var_password_pam_retry"'/' "$PAM_FILE_PATH"
        else
            sed -i -E --follow-symlinks 's/(\s*password\s+'"requisite"'\s+pam_pwquality.so\s+.*)('"retry"'=)[[:alnum:]]+\s*(.*)/\1\2'"$var_password_pam_retry"' \3/' "$PAM_FILE_PATH"
        fi
    if [ -f /usr/bin/authselect ]; then
        
        authselect apply-changes -b
    fi
else
    echo "/etc/pam.d/system-auth was not found" >&2
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi





# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_password_pam_ucredit='-1'






# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^ucredit")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_ucredit"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^ucredit\\>" "/etc/security/pwquality.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^ucredit\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
else
    if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
    fi
    cce="CCE-27200-5"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/security/pwquality.conf" >> "/etc/security/pwquality.conf"
    printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if rpm --quiet -q libuser; then

LIBUSER_CONF="/etc/libuser.conf"
CRYPT_STYLE_REGEX='[[:space:]]*\[defaults](.*(\n)+)+?[[:space:]]*crypt_style[[:space:]]*'

# Try find crypt_style in [defaults] section. If it is here, then change algorithm to sha512.
# If it isn't here, then add it to [defaults] section.
if grep -qzosP $CRYPT_STYLE_REGEX $LIBUSER_CONF ; then
        sed -i "s/\(crypt_style[[:space:]]*=[[:space:]]*\).*/\1sha512/g" $LIBUSER_CONF
elif grep -qs "\[defaults]" $LIBUSER_CONF ; then
        sed -i "/[[:space:]]*\[defaults]/a crypt_style = sha512" $LIBUSER_CONF
else
        echo -e "[defaults]\ncrypt_style = sha512" >> $LIBUSER_CONF
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi




# Remediation is applicable only in certain platforms
if rpm --quiet -q shadow-utils; then

var_password_hashing_algorithm='SHA512'


if grep --silent ^ENCRYPT_METHOD /etc/login.defs ; then
	sed -i "s/^ENCRYPT_METHOD .*/ENCRYPT_METHOD $var_password_hashing_algorithm/g" /etc/login.defs
else
	echo "" >> /etc/login.defs
	echo "ENCRYPT_METHOD $var_password_hashing_algorithm" >> /etc/login.defs
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi


# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

if [ -e "/etc/pam.d/password-auth" ] ; then
    PAM_FILE_PATH="/etc/pam.d/password-auth"
    if [ -f /usr/bin/authselect ]; then
        
        if ! authselect check; then
        echo "
        authselect integrity check failed. Remediation aborted!
        This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
        It is not recommended to manually edit the PAM files when authselect tool is available.
        In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
        exit 1
        fi

        CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
        # If not already in use, a custom profile is created preserving the enabled features.
        if [[ ! $CURRENT_PROFILE == custom/* ]]; then
            ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
            authselect create-profile hardening -b $CURRENT_PROFILE
            CURRENT_PROFILE="custom/hardening"
            
            authselect apply-changes -b --backup=before-hardening-custom-profile
            authselect select $CURRENT_PROFILE
            for feature in $ENABLED_FEATURES; do
                authselect enable-feature $feature;
            done
            
            authselect apply-changes -b --backup=after-hardening-custom-profile
        fi
        PAM_FILE_NAME=$(basename "/etc/pam.d/password-auth")
        PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

        authselect apply-changes -b
    fi
    if ! grep -qP '^\s*password\s+'"sufficient"'\s+pam_unix.so\s*.*' "$PAM_FILE_PATH"; then
            # Line matching group + control + module was not found. Check group + module.
            if [ "$(grep -cP '^\s*password\s+.*\s+pam_unix.so\s*' "$PAM_FILE_PATH")" -eq 1 ]; then
                # The control is updated only if one single line matches.
                sed -i -E --follow-symlinks 's/^(\s*password\s+).*(\bpam_unix.so.*)/\1'"sufficient"' \2/' "$PAM_FILE_PATH"
            else
                echo 'password    '"sufficient"'    pam_unix.so' >> "$PAM_FILE_PATH"
            fi
        fi
        # Check the option
        if ! grep -qP '^\s*password\s+'"sufficient"'\s+pam_unix.so\s*.*\ssha512\b' "$PAM_FILE_PATH"; then
            sed -i -E --follow-symlinks '/\s*password\s+'"sufficient"'\s+pam_unix.so.*/ s/$/ sha512/' "$PAM_FILE_PATH"
        fi
    if [ -f /usr/bin/authselect ]; then
        
        authselect apply-changes -b
    fi
else
    echo "/etc/pam.d/password-auth was not found" >&2
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi


# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

if [ -e "/etc/pam.d/system-auth" ] ; then
    PAM_FILE_PATH="/etc/pam.d/system-auth"
    if [ -f /usr/bin/authselect ]; then
        
        if ! authselect check; then
        echo "
        authselect integrity check failed. Remediation aborted!
        This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
        It is not recommended to manually edit the PAM files when authselect tool is available.
        In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
        exit 1
        fi

        CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
        # If not already in use, a custom profile is created preserving the enabled features.
        if [[ ! $CURRENT_PROFILE == custom/* ]]; then
            ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
            authselect create-profile hardening -b $CURRENT_PROFILE
            CURRENT_PROFILE="custom/hardening"
            
            authselect apply-changes -b --backup=before-hardening-custom-profile
            authselect select $CURRENT_PROFILE
            for feature in $ENABLED_FEATURES; do
                authselect enable-feature $feature;
            done
            
            authselect apply-changes -b --backup=after-hardening-custom-profile
        fi
        PAM_FILE_NAME=$(basename "/etc/pam.d/system-auth")
        PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

        authselect apply-changes -b
    fi
    if ! grep -qP '^\s*password\s+'"sufficient"'\s+pam_unix.so\s*.*' "$PAM_FILE_PATH"; then
            # Line matching group + control + module was not found. Check group + module.
            if [ "$(grep -cP '^\s*password\s+.*\s+pam_unix.so\s*' "$PAM_FILE_PATH")" -eq 1 ]; then
                # The control is updated only if one single line matches.
                sed -i -E --follow-symlinks 's/^(\s*password\s+).*(\bpam_unix.so.*)/\1'"sufficient"' \2/' "$PAM_FILE_PATH"
            else
                echo 'password    '"sufficient"'    pam_unix.so' >> "$PAM_FILE_PATH"
            fi
        fi
        # Check the option
        if ! grep -qP '^\s*password\s+'"sufficient"'\s+pam_unix.so\s*.*\ssha512\b' "$PAM_FILE_PATH"; then
            sed -i -E --follow-symlinks '/\s*password\s+'"sufficient"'\s+pam_unix.so.*/ s/$/ sha512/' "$PAM_FILE_PATH"
        fi
    if [ -f /usr/bin/authselect ]; then
        
        authselect apply-changes -b
    fi
else
    echo "/etc/pam.d/system-auth was not found" >&2
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

if [ -e "/etc/pam.d/postlogin" ] ; then
    PAM_FILE_PATH="/etc/pam.d/postlogin"
    if [ -f /usr/bin/authselect ]; then
        
        if ! authselect check; then
        echo "
        authselect integrity check failed. Remediation aborted!
        This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
        It is not recommended to manually edit the PAM files when authselect tool is available.
        In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
        exit 1
        fi

        CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
        # If not already in use, a custom profile is created preserving the enabled features.
        if [[ ! $CURRENT_PROFILE == custom/* ]]; then
            ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
            authselect create-profile hardening -b $CURRENT_PROFILE
            CURRENT_PROFILE="custom/hardening"
            
            authselect apply-changes -b --backup=before-hardening-custom-profile
            authselect select $CURRENT_PROFILE
            for feature in $ENABLED_FEATURES; do
                authselect enable-feature $feature;
            done
            
            authselect apply-changes -b --backup=after-hardening-custom-profile
        fi
        PAM_FILE_NAME=$(basename "/etc/pam.d/postlogin")
        PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

        authselect apply-changes -b
    fi
    if ! grep -qP '^\s*session\s+'"required"'\s+pam_lastlog.so\s*.*' "$PAM_FILE_PATH"; then
            # Line matching group + control + module was not found. Check group + module.
            if [ "$(grep -cP '^\s*session\s+.*\s+pam_lastlog.so\s*' "$PAM_FILE_PATH")" -eq 1 ]; then
                # The control is updated only if one single line matches.
                sed -i -E --follow-symlinks 's/^(\s*session\s+).*(\bpam_lastlog.so.*)/\1'"required"' \2/' "$PAM_FILE_PATH"
            else
                sed -i --follow-symlinks '1i session     '"required"'    pam_lastlog.so' "$PAM_FILE_PATH"
            fi
        fi
        # Check the option
        if ! grep -qP '^\s*session\s+'"required"'\s+pam_lastlog.so\s*.*\sshowfailed\b' "$PAM_FILE_PATH"; then
            sed -i -E --follow-symlinks '/\s*session\s+'"required"'\s+pam_lastlog.so.*/ s/$/ showfailed/' "$PAM_FILE_PATH"
        fi
    if [ -f /usr/bin/authselect ]; then
        
        authselect apply-changes -b
    fi
else
    echo "/etc/pam.d/postlogin was not found" >&2
fi
if [ -e "/etc/pam.d/postlogin" ] ; then
    PAM_FILE_PATH="/etc/pam.d/postlogin"
    if [ -f /usr/bin/authselect ]; then
        
        if ! authselect check; then
        echo "
        authselect integrity check failed. Remediation aborted!
        This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
        It is not recommended to manually edit the PAM files when authselect tool is available.
        In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
        exit 1
        fi

        CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
        # If not already in use, a custom profile is created preserving the enabled features.
        if [[ ! $CURRENT_PROFILE == custom/* ]]; then
            ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
            authselect create-profile hardening -b $CURRENT_PROFILE
            CURRENT_PROFILE="custom/hardening"
            
            authselect apply-changes -b --backup=before-hardening-custom-profile
            authselect select $CURRENT_PROFILE
            for feature in $ENABLED_FEATURES; do
                authselect enable-feature $feature;
            done
            
            authselect apply-changes -b --backup=after-hardening-custom-profile
        fi
        PAM_FILE_NAME=$(basename "/etc/pam.d/postlogin")
        PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

        authselect apply-changes -b
    fi
    
if grep -qP '^\s*session\s.*\bpam_lastlog.so\s.*\bsilent\b' "$PAM_FILE_PATH"; then
    sed -i -E --follow-symlinks 's/(.*session.*pam_lastlog.so.*)\bsilent\b=?[[:alnum:]]*(.*)/\1\2/g' "$PAM_FILE_PATH"
fi
    if [ -f /usr/bin/authselect ]; then
        
        authselect apply-changes -b
    fi
else
    echo "/etc/pam.d/postlogin was not found" >&2
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

if ! rpm -q --quiet "screen" ; then
    dnf install -y "screen"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && { ! grep -q s390x /proc/sys/kernel/osrelease; }; then

if ! rpm -q --quiet "pam_pkcs11" ; then
    dnf install -y "pam_pkcs11"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && { ! grep -q s390x /proc/sys/kernel/osrelease; }; then

# Install required packages
if ! rpm -q --quiet "esc" ; then
    dnf install -y "esc"
fi
if ! rpm -q --quiet "pam_pkcs11" ; then
    dnf install -y "pam_pkcs11"
fi

# Enable pcscd.socket systemd activation socket
/usr/bin/systemctl enable "pcscd.socket"
/usr/bin/systemctl start "pcscd.socket"
# The service may not be running because it has been started and failed,
# so let's reset the state so OVAL checks pass.
# Service should be 'inactive', not 'failed' after reboot though.
if /usr/bin/systemctl --failed | grep -q "pcscd.socket"; then
    /usr/bin/systemctl reset-failed "pcscd.socket"
fi

# Configure the expected /etc/pam.d/system-auth{,-ac} settings directly
#
# The code below will configure system authentication in the way smart card
# logins will be enabled, but also user login(s) via other method to be allowed
#
# NOTE: It is not possible to use the 'authconfig' command to perform the
#       remediation for us, because call of 'authconfig' would discard changes
#       for other remediations (see RH BZ#1357019 for details)
#
#	Therefore we need to configure the necessary settings directly.
#

# Define system-auth config location
SYSTEM_AUTH_CONF="/etc/pam.d/system-auth"
# Define expected 'pam_env.so' row in $SYSTEM_AUTH_CONF
PAM_ENV_SO="auth.*required.*pam_env\.so"
PAM_FAIL_DELAY="auth.*required.*pam_faildelay\.so"

# Define 'pam_succeed_if.so' row to be appended past $PAM_ENV_SO row into $SYSTEM_AUTH_CONF
SYSTEM_AUTH_PAM_SUCCEED="\
auth        [success=1 default=ignore] pam_succeed_if.so service notin \
login:gdm:xdm:kdm:xscreensaver:gnome-screensaver:kscreensaver quiet use_uid"
# Define 'pam_pkcs11.so' row to be appended past $SYSTEM_AUTH_PAM_SUCCEED
# row into SYSTEM_AUTH_CONF file
SYSTEM_AUTH_PAM_PKCS11="\
auth        [success=done authinfo_unavail=ignore ignore=ignore default=die] \
pam_pkcs11.so nodebug"

# Define smartcard-auth config location
SMARTCARD_AUTH_CONF="/etc/pam.d/smartcard-auth"
# Define 'pam_pkcs11.so' auth section to be appended past $PAM_ENV_SO into $SMARTCARD_AUTH_CONF
SMARTCARD_AUTH_SECTION="auth        [success=done ignore=ignore default=die] pam_pkcs11.so nodebug wait_for_card"
# Define expected 'pam_permit.so' row in $SMARTCARD_AUTH_CONF
PAM_PERMIT_SO="account.*required.*pam_permit\.so"
# Define 'pam_pkcs11.so' password section
SMARTCARD_PASSWORD_SECTION="password    required      pam_pkcs11.so"

# First Correct the SYSTEM_AUTH_CONF configuration
if ! grep -q 'pam_pkcs11.so' "$SYSTEM_AUTH_CONF"
then
    # Append pam_succeed_if.so row after pam_env.so or after pam_faildelay.so when it exists.
    # Then append pam_pkcs11.so row right after the pam_succeed_if.so we just added
    # in SYSTEM_AUTH_CONF file
    # This will preserve any other already existing row equal to "$SYSTEM_AUTH_PAM_SUCCEED"
    if ! grep -q 'pam_faildelay.so' "$SYSTEM_AUTH_CONF"
    then
        echo "$(awk '/^'"$PAM_ENV_SO"'/{print $0 RS "'"$SYSTEM_AUTH_PAM_SUCCEED"'" RS "'"$SYSTEM_AUTH_PAM_PKCS11"'";next}1' "$SYSTEM_AUTH_CONF")" > "$SYSTEM_AUTH_CONF"
    else
        echo "$(awk '/^'"$PAM_FAIL_DELAY"'/{print $0 RS "'"$SYSTEM_AUTH_PAM_SUCCEED"'" RS "'"$SYSTEM_AUTH_PAM_PKCS11"'";next}1' "$SYSTEM_AUTH_CONF")" > "$SYSTEM_AUTH_CONF"
    fi

fi

# Then also correct the SMARTCARD_AUTH_CONF
if ! grep -q 'auth.*pam_pkcs11\.so' "$SMARTCARD_AUTH_CONF"
then
	# Append (expected) SMARTCARD_AUTH_SECTION row past the pam_env.so into SMARTCARD_AUTH_CONF file
	sed -i --follow-symlinks -e '/^'"$PAM_ENV_SO"'/a \
        '"$SMARTCARD_AUTH_SECTION" "$SMARTCARD_AUTH_CONF"
else
    if ! grep -q 'auth.*pam_pkcs11\.so.*no_debug.*wait_for_card' "$SMARTCARD_AUTH_CONF"
    then
        sed -i --follow-symlinks -e 's/^auth.*pam_pkcs11\.so.*/'"$SMARTCARD_AUTH_SECTION"'/' "$SMARTCARD_AUTH_CONF"
    fi
fi
if ! grep -q 'password.*pam_pkcs11\.so' "$SMARTCARD_AUTH_CONF"
then
	# Append (expected) SMARTCARD_PASSWORD_SECTION row past the pam_permit.so into SMARTCARD_AUTH_CONF file
	sed -i --follow-symlinks -e '/^'"$PAM_PERMIT_SO"'/a \
        '"$SMARTCARD_PASSWORD_SECTION" "$SMARTCARD_AUTH_CONF"
else
    if ! grep -q 'password.*required.*pam_pkcs11\.so' "$SMARTCARD_AUTH_CONF"
    then
        sed -i --follow-symlinks -e 's/password.*pam_pkcs11\.so.*/'"$SMARTCARD_PASSWORD_SECTION"'/' "$SMARTCARD_AUTH_CONF"
    fi
fi

# Perform /etc/pam_pkcs11/pam_pkcs11.conf settings below
# Define selected constants for later reuse
SP="[:space:]"
PAM_PKCS11_CONF="/etc/pam_pkcs11/pam_pkcs11.conf"

# Ensure OCSP is turned on in $PAM_PKCS11_CONF
# 1) First replace any occurrence of 'none' value of 'cert_policy' key setting with the correct configuration
sed -i "s/^[$SP]*cert_policy[$SP]\+=[$SP]\+none;/\t\tcert_policy = ca, ocsp_on, signature;/g" "$PAM_PKCS11_CONF"
# 2) Then append 'ocsp_on' value setting to each 'cert_policy' key in $PAM_PKCS11_CONF configuration line,
# which does not contain it yet
sed -i "/ocsp_on/! s/^[$SP]*cert_policy[$SP]\+=[$SP]\+\(.*\);/\t\tcert_policy = \1, ocsp_on;/" "$PAM_PKCS11_CONF"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi





# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && { ! grep -q s390x /proc/sys/kernel/osrelease; }; then

if ! rpm -q --quiet "pam_pkcs11" ; then
    dnf install -y "pam_pkcs11"
fi

if grep "^\s*cert_policy" /etc/pam_pkcs11/pam_pkcs11.conf | grep -qv "ocsp_on"; then
	sed -i "/^\s*#/! s/cert_policy.*/cert_policy = ca, ocsp_on, signature;/g" /etc/pam_pkcs11/pam_pkcs11.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

systemctl disable --now ctrl-alt-del.target
systemctl mask --now ctrl-alt-del.target

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

service_file="/usr/lib/systemd/system/rescue.service"

sulogin='/bin/sh -c "/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"'

if grep "^ExecStart=.*" "$service_file" ; then
    sed -i "s%^ExecStart=.*%ExecStart=-$sulogin%" "$service_file"
else
    echo "ExecStart=-$sulogin" >> "$service_file"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if rpm --quiet -q shadow-utils; then

var_account_disable_post_pw_expiration='35'


# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^INACTIVE")

# shellcheck disable=SC2059
printf -v formatted_output "%s=%s" "$stripped_key" "$var_account_disable_post_pw_expiration"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^INACTIVE\\>" "/etc/default/useradd"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^INACTIVE\\>.*/$escaped_formatted_output/gi" "/etc/default/useradd"
else
    if [[ -s "/etc/default/useradd" ]] && [[ -n "$(tail -c 1 -- "/etc/default/useradd" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/default/useradd"
    fi
    cce="CCE-27355-7"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/default/useradd" >> "/etc/default/useradd"
    printf '%s\n' "$formatted_output" >> "/etc/default/useradd"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if rpm --quiet -q shadow-utils; then

var_accounts_maximum_age_login_defs='60'


grep -q ^PASS_MAX_DAYS /etc/login.defs && \
  sed -i "s/PASS_MAX_DAYS.*/PASS_MAX_DAYS     $var_accounts_maximum_age_login_defs/g" /etc/login.defs
if ! [ $? -eq 0 ]; then
    echo "PASS_MAX_DAYS      $var_accounts_maximum_age_login_defs" >> /etc/login.defs
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi


# Remediation is applicable only in certain platforms
if rpm --quiet -q shadow-utils; then

var_accounts_minimum_age_login_defs='1'


grep -q ^PASS_MIN_DAYS /etc/login.defs && \
  sed -i "s/PASS_MIN_DAYS.*/PASS_MIN_DAYS     $var_accounts_minimum_age_login_defs/g" /etc/login.defs
if ! [ $? -eq 0 ]; then
    echo "PASS_MIN_DAYS      $var_accounts_minimum_age_login_defs" >> /etc/login.defs
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi


var_accounts_maximum_age_login_defs='60'


while IFS= read -r i; do
    
    chage -M $var_accounts_maximum_age_login_defs $i

done <   <(awk -v var="$var_accounts_maximum_age_login_defs" -F: '(/^[^:]+:[^!*]/ && ($5 > var || $5 == "")) {print $1}' /etc/shadow)


var_accounts_minimum_age_login_defs='1'


while IFS= read -r i; do
    
    chage -m $var_accounts_minimum_age_login_defs $i

done <   <(awk -v var="$var_accounts_minimum_age_login_defs" -F: '(/^[^:]+:[^!*]/ && ($4 < var || $4 == "")) {print $1}' /etc/shadow)


# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

if [ -f /usr/bin/authselect ]; then
    if ! authselect check; then
echo "
authselect integrity check failed. Remediation aborted!
This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
It is not recommended to manually edit the PAM files when authselect tool is available.
In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
exit 1
fi
authselect enable-feature without-nullok

authselect apply-changes -b
else
    
if grep -qP '^\s*auth\s+'"sufficient"'\s+pam_unix.so\s.*\bnullok\b' "/etc/pam.d/system-auth"; then
    sed -i -E --follow-symlinks 's/(.*auth.*'"sufficient"'.*pam_unix.so.*)\snullok=?[[:alnum:]]*(.*)/\1\2/g' "/etc/pam.d/system-auth"
fi
    
if grep -qP '^\s*password\s+'"sufficient"'\s+pam_unix.so\s.*\bnullok\b' "/etc/pam.d/system-auth"; then
    sed -i -E --follow-symlinks 's/(.*password.*'"sufficient"'.*pam_unix.so.*)\snullok=?[[:alnum:]]*(.*)/\1\2/g' "/etc/pam.d/system-auth"
fi
    
if grep -qP '^\s*auth\s+'"sufficient"'\s+pam_unix.so\s.*\bnullok\b' "/etc/pam.d/password-auth"; then
    sed -i -E --follow-symlinks 's/(.*auth.*'"sufficient"'.*pam_unix.so.*)\snullok=?[[:alnum:]]*(.*)/\1\2/g' "/etc/pam.d/password-auth"
fi
    
if grep -qP '^\s*password\s+'"sufficient"'\s+pam_unix.so\s.*\bnullok\b' "/etc/pam.d/password-auth"; then
    sed -i -E --follow-symlinks 's/(.*password.*'"sufficient"'.*pam_unix.so.*)\snullok=?[[:alnum:]]*(.*)/\1\2/g' "/etc/pam.d/password-auth"
fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



awk -F: '$3 == 0 && $1 != "root" { print $1 }' /etc/passwd | xargs --no-run-if-empty --max-lines=1 passwd -l


# Remediation is applicable only in certain platforms
if rpm --quiet -q shadow-utils; then

var_accounts_user_umask='077'


# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^UMASK")

# shellcheck disable=SC2059
printf -v formatted_output "%s %s" "$stripped_key" "$var_accounts_user_umask"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^UMASK\\>" "/etc/login.defs"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^UMASK\\>.*/$escaped_formatted_output/gi" "/etc/login.defs"
else
    if [[ -s "/etc/login.defs" ]] && [[ -n "$(tail -c 1 -- "/etc/login.defs" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/login.defs"
    fi
    cce="CCE-80205-8"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/login.defs" >> "/etc/login.defs"
    printf '%s\n' "$formatted_output" >> "/etc/login.defs"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi


while IFS= read -r dir; do
    while IFS= read -r -d '' file; do
        if [ "$(basename $file)" != ".bash_history" ]; then
            sed -i 's/^\([\s]*umask\s*\)/#\1/g' "$file"
        fi
    done <   <(find $dir -maxdepth 1 -type f -name ".*" -print0)
done <   <(awk -F':' '{ if ($3 >= 1000 && $3 != 65534) print $6}' /etc/passwd)



# Remediation is applicable only in certain platforms
if rpm --quiet -q shadow-utils; then

if [ -e "/etc/login.defs" ] ; then
    
    LC_ALL=C sed -i "/^\s*CREATE_HOME\s\+/Id" "/etc/login.defs"
else
    touch "/etc/login.defs"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/login.defs"

cp "/etc/login.defs" "/etc/login.defs.bak"
# Insert before the line matching the regex '^\s*CREATE_HOME'.
line_number="$(LC_ALL=C grep -n "^\s*CREATE_HOME" "/etc/login.defs.bak" | LC_ALL=C sed 's/:.*//g')"
if [ -z "$line_number" ]; then
    # There was no match of '^\s*CREATE_HOME', insert at
    # the end of the file.
    printf '%s\n' "CREATE_HOME yes" >> "/etc/login.defs"
else
    head -n "$(( line_number - 1 ))" "/etc/login.defs.bak" > "/etc/login.defs"
    printf '%s\n' "CREATE_HOME yes" >> "/etc/login.defs"
    tail -n "+$(( line_number ))" "/etc/login.defs.bak" >> "/etc/login.defs"
fi
# Clean up after ourselves.
rm "/etc/login.defs.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if rpm --quiet -q shadow-utils; then

var_accounts_fail_delay='4'


# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^FAIL_DELAY")

# shellcheck disable=SC2059
printf -v formatted_output "%s %s" "$stripped_key" "$var_accounts_fail_delay"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^FAIL_DELAY\\>" "/etc/login.defs"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^FAIL_DELAY\\>.*/$escaped_formatted_output/gi" "/etc/login.defs"
else
    if [[ -s "/etc/login.defs" ]] && [[ -n "$(tail -c 1 -- "/etc/login.defs" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/login.defs"
    fi
    cce="CCE-80352-8"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/login.defs" >> "/etc/login.defs"
    printf '%s\n' "$formatted_output" >> "/etc/login.defs"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi


# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_accounts_max_concurrent_login_sessions='10'


if grep -q '^[^#]*\<maxlogins\>' /etc/security/limits.d/*.conf; then
	sed -i "/^[^#]*\<maxlogins\>/ s/maxlogins.*/maxlogins $var_accounts_max_concurrent_login_sessions/" /etc/security/limits.d/*.conf
elif grep -q '^[^#]*\<maxlogins\>' /etc/security/limits.conf; then
	sed -i "/^[^#]*\<maxlogins\>/ s/maxlogins.*/maxlogins $var_accounts_max_concurrent_login_sessions/" /etc/security/limits.conf
else
	echo "*	hard	maxlogins	$var_accounts_max_concurrent_login_sessions" >> /etc/security/limits.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

var_accounts_tmout='900'


# if 0, no occurence of tmout found, if 1, occurence found
tmout_found=0


for f in /etc/profile /etc/profile.d/*.sh /etc/bashrc; do

    if grep --silent '^[^#].*TMOUT' $f; then
        sed -i -E "s/^(.*)TMOUT\s*=\s*(\w|\$)*(.*)$/declare -xr TMOUT=$var_accounts_tmout\3/g" $f
        tmout_found=1
    fi
done

if [ $tmout_found -eq 0 ]; then
        echo -e "\n# Set TMOUT to $var_accounts_tmout per security requirements" >> /etc/profile.d/tmout.sh
        echo "declare -xr TMOUT=$var_accounts_tmout" >> /etc/profile.d/tmout.sh
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



awk -F':' '{ if ($3 >= 1000 && $3 != 65534) system("chgrp -f " $4" "$6"/.[^\.]?*") }' /etc/passwd


readarray -t world_writable_files < <(find / -xdev -type f -perm -0002 2> /dev/null)
readarray -t interactive_home_dirs < <(awk -F':' '{ if ($3 >= 1000 && $3 != 65534) print $6 }' /etc/passwd)

for world_writable in "${world_writable_files[@]}"; do
    for homedir in "${interactive_home_dirs[@]}"; do
        if grep -q -d skip "$world_writable" "$homedir"/.*; then
            chmod o-w $world_writable
            break
        fi
    done
done


awk -F':' '{ if ($3 >= 1000 && $3 != 65534) system("chown -f " $3" "$6"/.[^\.]?*") }' /etc/passwd


for user in $(awk -F':' '{ if ($3 >= 1000 && $3 != 65534) print $1}' /etc/passwd); do
    mkhomedir_helper $user 0077;
done


for user in $(awk -F':' '{ if ($3 >= 1000 && $3 != 65534) print $1 }' /etc/passwd); do
    home_dir=$(getent passwd $user | cut -d: -f6)
    group=$(getent passwd $user | cut -d: -f4)
    # Only update the group-ownership when necessary. This will avoid changing the inode timestamp
    # when the group is already defined as expected, therefore not impacting in possible integrity
    # check systems that also check inodes timestamps.
    find $home_dir -not -group $group -exec chgrp -f $group {} \;
done


for user in $(awk -F':' '{ if ($3 >= 1000 && $3 != 65534) print $1 }' /etc/passwd); do
    home_dir=$(getent passwd $user | cut -d: -f6)
    # Only update the ownership when necessary. This will avoid changing the inode timestamp
    # when the owner is already defined as expected, therefore not impacting in possible integrity
    # check systems that also check inodes timestamps.
    find $home_dir -not -user $user -exec chown -f $user {} \;
done


for home_dir in $(awk -F':' '{ if ($3 >= 1000 && $3 != 65534) print $6 }' /etc/passwd); do
    # Only update the permissions when necessary. This will avoid changing the inode timestamp when
    # the permission is already defined as expected, therefore not impacting in possible integrity
    # check systems that also check inodes timestamps.
    find "$home_dir" -perm /7027 -exec chmod u-s,g-w-s,o=- {} \;
done



awk -F':' '{ if ($3 >= 1000 && $3 != 65534) system("chgrp -f " $4" "$6) }' /etc/passwd


awk -F':' '{ if ($3 >= 1000 && $3 != 65534) system("chown -f " $3" "$6) }' /etc/passwd


for home_dir in $(awk -F':' '{ if ($3 >= 1000 && $3 != 65534) print $6 }' /etc/passwd); do
    # Only update the permissions when necessary. This will avoid changing the inode timestamp when
    # the permission is already defined as expected, therefore not impacting in possible integrity
    # check systems that also check inodes timestamps.
    find "$home_dir" -maxdepth 0 -perm /7027 -exec chmod u-s,g-w-s,o=- {} \;
done


# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="chmod"
	KEY="perm_mod"
	SYSCALL_GROUPING="chmod fchmod fchmodat"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi


# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="chown"
	KEY="perm_mod"
	SYSCALL_GROUPING="chown fchown fchownat lchown"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="fchmod"
	KEY="perm_mod"
	SYSCALL_GROUPING="chmod fchmod fchmodat"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi


# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="fchmodat"
	KEY="perm_mod"
	SYSCALL_GROUPING="chmod fchmod fchmodat"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi


# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="fchown"
	KEY="perm_mod"
	SYSCALL_GROUPING="chown fchown fchownat lchown"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi


# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="fchownat"
	KEY="perm_mod"
	SYSCALL_GROUPING="chown fchown fchownat lchown"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi


# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="fremovexattr"
	KEY="perm_mod"
	SYSCALL_GROUPING="fremovexattr lremovexattr removexattr fsetxattr lsetxattr setxattr"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi


# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="fsetxattr"
	KEY="perm_mod"
	SYSCALL_GROUPING="fremovexattr lremovexattr removexattr fsetxattr lsetxattr setxattr"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="lchown"
	KEY="perm_mod"
	SYSCALL_GROUPING="chown fchown fchownat lchown"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi




# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="lremovexattr"
	KEY="perm_mod"
	SYSCALL_GROUPING="fremovexattr lremovexattr removexattr fsetxattr lsetxattr setxattr"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="lsetxattr"
	KEY="perm_mod"
	SYSCALL_GROUPING="fremovexattr lremovexattr removexattr fsetxattr lsetxattr setxattr"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi


# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="removexattr"
	KEY="perm_mod"
	SYSCALL_GROUPING="fremovexattr lremovexattr removexattr fsetxattr lsetxattr setxattr"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="setxattr"
	KEY="perm_mod"
	SYSCALL_GROUPING="fremovexattr lremovexattr removexattr fsetxattr lsetxattr setxattr"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi


# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/bin/chcon -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi




# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/sbin/semanage -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/sbin/setfiles -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi




# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/sbin/setsebool -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="rename"
	KEY="delete"
	SYSCALL_GROUPING="unlink unlinkat rename renameat rmdir"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi




# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="renameat"
	KEY="delete"
	SYSCALL_GROUPING="unlink unlinkat rename renameat rmdir"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi


# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="rmdir"
	KEY="delete"
	SYSCALL_GROUPING="unlink unlinkat rename renameat rmdir"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="unlink"
	KEY="delete"
	SYSCALL_GROUPING="unlink unlinkat rename renameat rmdir"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi


# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="unlinkat"
	KEY="delete"
	SYSCALL_GROUPING="unlink unlinkat rename renameat rmdir"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi


# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
# Note: 32-bit and 64-bit kernel syscall numbers not always line up =>
#       it's required on a 64-bit system to check also for the presence
#       of 32-bit's equivalent of the corresponding rule.
#       (See `man 7 audit.rules` for details )
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS=""
	SYSCALL="create_module"
	KEY="module-change"
	SYSCALL_GROUPING=""

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
# Note: 32-bit and 64-bit kernel syscall numbers not always line up =>
#       it's required on a 64-bit system to check also for the presence
#       of 32-bit's equivalent of the corresponding rule.
#       (See `man 7 audit.rules` for details )
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	
	SYSCALL="delete_module"
	KEY="modules"
	SYSCALL_GROUPING="delete_module"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
# Note: 32-bit and 64-bit kernel syscall numbers not always line up =>
#       it's required on a 64-bit system to check also for the presence
#       of 32-bit's equivalent of the corresponding rule.
#       (See `man 7 audit.rules` for details )
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	
	SYSCALL="finit_module"
	KEY="modules"
	SYSCALL_GROUPING="init_module finit_module"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi




# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
# Note: 32-bit and 64-bit kernel syscall numbers not always line up =>
#       it's required on a 64-bit system to check also for the presence
#       of 32-bit's equivalent of the corresponding rule.
#       (See `man 7 audit.rules` for details )
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	
	SYSCALL="init_module"
	KEY="modules"
	SYSCALL_GROUPING="init_module finit_module"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()


# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
files_to_inspect+=('/etc/audit/audit.rules')

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/var/run/faillock" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/var/run/faillock $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/var/run/faillock$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /var/run/faillock -p wa -k logins" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()

# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/logins.rules' to list of files for inspection.
readarray -t matches < <(grep -HP "[\s]*-w[\s]+/var/run/faillock" /etc/audit/rules.d/*.rules)

# For each of the matched entries
for match in "${matches[@]}"
do
    # Extract filepath from the match
    rulesd_audit_file=$(echo $match | cut -f1 -d ':')
    # Append that path into list of files for inspection
    files_to_inspect+=("$rulesd_audit_file")
done
# Case when particular audit rule isn't defined yet
if [ "${#files_to_inspect[@]}" -eq "0" ]
then
    # Append '/etc/audit/rules.d/logins.rules' into list of files for inspection
    key_rule_file="/etc/audit/rules.d/logins.rules"
    # If the logins.rules file doesn't exist yet, create it with correct permissions
    if [ ! -e "$key_rule_file" ]
    then
        touch "$key_rule_file"
        chmod 0640 "$key_rule_file"
    fi
    files_to_inspect+=("$key_rule_file")
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/var/run/faillock" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/var/run/faillock $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/var/run/faillock$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /var/run/faillock -p wa -k logins" >> "$audit_rules_file"
    fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi


# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()


# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
files_to_inspect+=('/etc/audit/audit.rules')

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/var/log/lastlog" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/var/log/lastlog $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/var/log/lastlog$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /var/log/lastlog -p wa -k logins" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()

# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/logins.rules' to list of files for inspection.
readarray -t matches < <(grep -HP "[\s]*-w[\s]+/var/log/lastlog" /etc/audit/rules.d/*.rules)

# For each of the matched entries
for match in "${matches[@]}"
do
    # Extract filepath from the match
    rulesd_audit_file=$(echo $match | cut -f1 -d ':')
    # Append that path into list of files for inspection
    files_to_inspect+=("$rulesd_audit_file")
done
# Case when particular audit rule isn't defined yet
if [ "${#files_to_inspect[@]}" -eq "0" ]
then
    # Append '/etc/audit/rules.d/logins.rules' into list of files for inspection
    key_rule_file="/etc/audit/rules.d/logins.rules"
    # If the logins.rules file doesn't exist yet, create it with correct permissions
    if [ ! -e "$key_rule_file" ]
    then
        touch "$key_rule_file"
        chmod 0640 "$key_rule_file"
    fi
    files_to_inspect+=("$key_rule_file")
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/var/log/lastlog" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/var/log/lastlog $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/var/log/lastlog$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /var/log/lastlog -p wa -k logins" >> "$audit_rules_file"
    fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi




# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="mount"
	KEY="perm_mod"
	SYSCALL_GROUPING=""

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi




# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	
	OTHER_FILTERS="-C uid!=euid -F euid=0"
	
	AUID_FILTERS=""
	SYSCALL="execve"
	KEY="setuid"
	SYSCALL_GROUPING=""
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	
	OTHER_FILTERS="-C gid!=egid -F egid=0"
	
	AUID_FILTERS=""
	SYSCALL="execve"
	KEY="setgid"
	SYSCALL_GROUPING=""
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi




# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()


# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
files_to_inspect+=('/etc/audit/audit.rules')

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/sudoers" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/sudoers $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/sudoers$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/sudoers -p wa -k actions" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()

# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/actions.rules' to list of files for inspection.
readarray -t matches < <(grep -HP "[\s]*-w[\s]+/etc/sudoers" /etc/audit/rules.d/*.rules)

# For each of the matched entries
for match in "${matches[@]}"
do
    # Extract filepath from the match
    rulesd_audit_file=$(echo $match | cut -f1 -d ':')
    # Append that path into list of files for inspection
    files_to_inspect+=("$rulesd_audit_file")
done
# Case when particular audit rule isn't defined yet
if [ "${#files_to_inspect[@]}" -eq "0" ]
then
    # Append '/etc/audit/rules.d/actions.rules' into list of files for inspection
    key_rule_file="/etc/audit/rules.d/actions.rules"
    # If the actions.rules file doesn't exist yet, create it with correct permissions
    if [ ! -e "$key_rule_file" ]
    then
        touch "$key_rule_file"
        chmod 0640 "$key_rule_file"
    fi
    files_to_inspect+=("$key_rule_file")
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/sudoers" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/sudoers $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/sudoers$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/sudoers -p wa -k actions" >> "$audit_rules_file"
    fi
done

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()


# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
files_to_inspect+=('/etc/audit/audit.rules')

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/sudoers.d/" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/sudoers.d/ $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/sudoers.d/$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/sudoers.d/ -p wa -k actions" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()

# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/actions.rules' to list of files for inspection.
readarray -t matches < <(grep -HP "[\s]*-w[\s]+/etc/sudoers.d/" /etc/audit/rules.d/*.rules)

# For each of the matched entries
for match in "${matches[@]}"
do
    # Extract filepath from the match
    rulesd_audit_file=$(echo $match | cut -f1 -d ':')
    # Append that path into list of files for inspection
    files_to_inspect+=("$rulesd_audit_file")
done
# Case when particular audit rule isn't defined yet
if [ "${#files_to_inspect[@]}" -eq "0" ]
then
    # Append '/etc/audit/rules.d/actions.rules' into list of files for inspection
    key_rule_file="/etc/audit/rules.d/actions.rules"
    # If the actions.rules file doesn't exist yet, create it with correct permissions
    if [ ! -e "$key_rule_file" ]
    then
        touch "$key_rule_file"
        chmod 0640 "$key_rule_file"
    fi
    files_to_inspect+=("$key_rule_file")
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/sudoers.d/" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/sudoers.d/ $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/sudoers.d/$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/sudoers.d/ -p wa -k actions" >> "$audit_rules_file"
    fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi





# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

var_audit_failure_mode='2'


# Traverse all of:
#
# /etc/audit/audit.rules,			(for auditctl case)
# /etc/audit/rules.d/*.rules			(for augenrules case)
find /etc/audit /etc/audit/rules.d -maxdepth 1 -type f -name '*.rules' -exec sed -i '/-f[[:space:]]\+.*/d' {} ';'

for AUDIT_FILE in "/etc/audit/audit.rules" "/etc/audit/rules.d/immutable.rules"
do
	echo '' >> $AUDIT_FILE
	echo '# Set the audit.rules configuration to halt system upon audit failure per security requirements' >> $AUDIT_FILE
	echo "-f $var_audit_failure_mode" >> $AUDIT_FILE
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()


# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
files_to_inspect+=('/etc/audit/audit.rules')

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/group" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/group $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/group$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/group -p wa -k audit_rules_usergroup_modification" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()

# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/audit_rules_usergroup_modification.rules' to list of files for inspection.
readarray -t matches < <(grep -HP "[\s]*-w[\s]+/etc/group" /etc/audit/rules.d/*.rules)

# For each of the matched entries
for match in "${matches[@]}"
do
    # Extract filepath from the match
    rulesd_audit_file=$(echo $match | cut -f1 -d ':')
    # Append that path into list of files for inspection
    files_to_inspect+=("$rulesd_audit_file")
done
# Case when particular audit rule isn't defined yet
if [ "${#files_to_inspect[@]}" -eq "0" ]
then
    # Append '/etc/audit/rules.d/audit_rules_usergroup_modification.rules' into list of files for inspection
    key_rule_file="/etc/audit/rules.d/audit_rules_usergroup_modification.rules"
    # If the audit_rules_usergroup_modification.rules file doesn't exist yet, create it with correct permissions
    if [ ! -e "$key_rule_file" ]
    then
        touch "$key_rule_file"
        chmod 0640 "$key_rule_file"
    fi
    files_to_inspect+=("$key_rule_file")
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/group" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/group $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/group$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/group -p wa -k audit_rules_usergroup_modification" >> "$audit_rules_file"
    fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi




# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()


# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
files_to_inspect+=('/etc/audit/audit.rules')

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/gshadow" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/gshadow $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/gshadow$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/gshadow -p wa -k audit_rules_usergroup_modification" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()

# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/audit_rules_usergroup_modification.rules' to list of files for inspection.
readarray -t matches < <(grep -HP "[\s]*-w[\s]+/etc/gshadow" /etc/audit/rules.d/*.rules)

# For each of the matched entries
for match in "${matches[@]}"
do
    # Extract filepath from the match
    rulesd_audit_file=$(echo $match | cut -f1 -d ':')
    # Append that path into list of files for inspection
    files_to_inspect+=("$rulesd_audit_file")
done
# Case when particular audit rule isn't defined yet
if [ "${#files_to_inspect[@]}" -eq "0" ]
then
    # Append '/etc/audit/rules.d/audit_rules_usergroup_modification.rules' into list of files for inspection
    key_rule_file="/etc/audit/rules.d/audit_rules_usergroup_modification.rules"
    # If the audit_rules_usergroup_modification.rules file doesn't exist yet, create it with correct permissions
    if [ ! -e "$key_rule_file" ]
    then
        touch "$key_rule_file"
        chmod 0640 "$key_rule_file"
    fi
    files_to_inspect+=("$key_rule_file")
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/gshadow" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/gshadow $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/gshadow$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/gshadow -p wa -k audit_rules_usergroup_modification" >> "$audit_rules_file"
    fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi




# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()


# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
files_to_inspect+=('/etc/audit/audit.rules')

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/security/opasswd" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/security/opasswd $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/security/opasswd$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/security/opasswd -p wa -k audit_rules_usergroup_modification" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()

# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/audit_rules_usergroup_modification.rules' to list of files for inspection.
readarray -t matches < <(grep -HP "[\s]*-w[\s]+/etc/security/opasswd" /etc/audit/rules.d/*.rules)

# For each of the matched entries
for match in "${matches[@]}"
do
    # Extract filepath from the match
    rulesd_audit_file=$(echo $match | cut -f1 -d ':')
    # Append that path into list of files for inspection
    files_to_inspect+=("$rulesd_audit_file")
done
# Case when particular audit rule isn't defined yet
if [ "${#files_to_inspect[@]}" -eq "0" ]
then
    # Append '/etc/audit/rules.d/audit_rules_usergroup_modification.rules' into list of files for inspection
    key_rule_file="/etc/audit/rules.d/audit_rules_usergroup_modification.rules"
    # If the audit_rules_usergroup_modification.rules file doesn't exist yet, create it with correct permissions
    if [ ! -e "$key_rule_file" ]
    then
        touch "$key_rule_file"
        chmod 0640 "$key_rule_file"
    fi
    files_to_inspect+=("$key_rule_file")
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/security/opasswd" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/security/opasswd $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/security/opasswd$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/security/opasswd -p wa -k audit_rules_usergroup_modification" >> "$audit_rules_file"
    fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi




# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()


# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
files_to_inspect+=('/etc/audit/audit.rules')

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/passwd" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/passwd $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/passwd$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/passwd -p wa -k audit_rules_usergroup_modification" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()

# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/audit_rules_usergroup_modification.rules' to list of files for inspection.
readarray -t matches < <(grep -HP "[\s]*-w[\s]+/etc/passwd" /etc/audit/rules.d/*.rules)

# For each of the matched entries
for match in "${matches[@]}"
do
    # Extract filepath from the match
    rulesd_audit_file=$(echo $match | cut -f1 -d ':')
    # Append that path into list of files for inspection
    files_to_inspect+=("$rulesd_audit_file")
done
# Case when particular audit rule isn't defined yet
if [ "${#files_to_inspect[@]}" -eq "0" ]
then
    # Append '/etc/audit/rules.d/audit_rules_usergroup_modification.rules' into list of files for inspection
    key_rule_file="/etc/audit/rules.d/audit_rules_usergroup_modification.rules"
    # If the audit_rules_usergroup_modification.rules file doesn't exist yet, create it with correct permissions
    if [ ! -e "$key_rule_file" ]
    then
        touch "$key_rule_file"
        chmod 0640 "$key_rule_file"
    fi
    files_to_inspect+=("$key_rule_file")
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/passwd" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/passwd $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/passwd$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/passwd -p wa -k audit_rules_usergroup_modification" >> "$audit_rules_file"
    fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi


# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()


# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
files_to_inspect+=('/etc/audit/audit.rules')

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/shadow" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/shadow $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/shadow$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/shadow -p wa -k audit_rules_usergroup_modification" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()

# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/audit_rules_usergroup_modification.rules' to list of files for inspection.
readarray -t matches < <(grep -HP "[\s]*-w[\s]+/etc/shadow" /etc/audit/rules.d/*.rules)

# For each of the matched entries
for match in "${matches[@]}"
do
    # Extract filepath from the match
    rulesd_audit_file=$(echo $match | cut -f1 -d ':')
    # Append that path into list of files for inspection
    files_to_inspect+=("$rulesd_audit_file")
done
# Case when particular audit rule isn't defined yet
if [ "${#files_to_inspect[@]}" -eq "0" ]
then
    # Append '/etc/audit/rules.d/audit_rules_usergroup_modification.rules' into list of files for inspection
    key_rule_file="/etc/audit/rules.d/audit_rules_usergroup_modification.rules"
    # If the audit_rules_usergroup_modification.rules file doesn't exist yet, create it with correct permissions
    if [ ! -e "$key_rule_file" ]
    then
        touch "$key_rule_file"
        chmod 0640 "$key_rule_file"
    fi
    files_to_inspect+=("$key_rule_file")
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/shadow" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/shadow $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/shadow$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/shadow -p wa -k audit_rules_usergroup_modification" >> "$audit_rules_file"
    fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi




# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

if LC_ALL=C grep -m 1 -q ^log_group /etc/audit/auditd.conf; then
  GROUP=$(awk -F "=" '/log_group/ {print $2}' /etc/audit/auditd.conf | tr -d ' ')
  if ! [ "${GROUP}" == 'root' ] ; then
    chown root:${GROUP} /var/log/audit
    chown root:${GROUP} /var/log/audit/audit.log*
  else
    chown root:root /var/log/audit
    chown root:root /var/log/audit/audit.log*
  fi
else
  chown root:root /var/log/audit
  chown root:root /var/log/audit/audit.log*
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

if LC_ALL=C grep -iw ^log_file /etc/audit/auditd.conf; then
    FILE=$(awk -F "=" '/^log_file/ {print $2}' /etc/audit/auditd.conf | tr -d ' ')
else
    FILE="/var/log/audit/audit.log"
fi


chmod 0600 $FILE

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi


# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

var_audispd_remote_server='logcollector'


AUDITCONFIG=/etc/audisp/audisp-remote.conf



# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^remote_server")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$var_audispd_remote_server"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^remote_server\\>" "$AUDITCONFIG"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^remote_server\\>.*/$escaped_formatted_output/gi" "$AUDITCONFIG"
else
    if [[ -s "$AUDITCONFIG" ]] && [[ -n "$(tail -c 1 -- "$AUDITCONFIG" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "$AUDITCONFIG"
    fi
    cce="CCE-80541-6"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "$AUDITCONFIG" >> "$AUDITCONFIG"
    printf '%s\n' "$formatted_output" >> "$AUDITCONFIG"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

var_audispd_disk_full_action='single'


AUDITCONFIG=/etc/audisp/audisp-remote.conf

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^disk_full_action")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$var_audispd_disk_full_action"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^disk_full_action\\>" "$AUDITCONFIG"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^disk_full_action\\>.*/$escaped_formatted_output/gi" "$AUDITCONFIG"
else
    if [[ -s "$AUDITCONFIG" ]] && [[ -n "$(tail -c 1 -- "$AUDITCONFIG" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "$AUDITCONFIG"
    fi
    cce="CCE-80539-0"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "$AUDITCONFIG" >> "$AUDITCONFIG"
    printf '%s\n' "$formatted_output" >> "$AUDITCONFIG"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi




# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

AUDISP_REMOTE_CONFIG="/etc/audisp/audisp-remote.conf"

option="^enable_krb5"
value="yes"


# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$option")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$value"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "$option\\>" "$AUDISP_REMOTE_CONFIG"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/$option\\>.*/$escaped_formatted_output/gi" "$AUDISP_REMOTE_CONFIG"
else
    if [[ -s "$AUDISP_REMOTE_CONFIG" ]] && [[ -n "$(tail -c 1 -- "$AUDISP_REMOTE_CONFIG" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "$AUDISP_REMOTE_CONFIG"
    fi
    cce="CCE-80540-8"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "$AUDISP_REMOTE_CONFIG" >> "$AUDISP_REMOTE_CONFIG"
    printf '%s\n' "$formatted_output" >> "$AUDISP_REMOTE_CONFIG"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

var_audispd_network_failure_action='single'


AUDITCONFIG=/etc/audisp/audisp-remote.conf

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^network_failure_action")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$var_audispd_network_failure_action"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^network_failure_action\\>" "$AUDITCONFIG"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^network_failure_action\\>.*/$escaped_formatted_output/gi" "$AUDITCONFIG"
else
    if [[ -s "$AUDITCONFIG" ]] && [[ -n "$(tail -c 1 -- "$AUDITCONFIG" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "$AUDITCONFIG"
    fi
    cce="CCE-80538-2"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "$AUDITCONFIG" >> "$AUDITCONFIG"
    printf '%s\n' "$formatted_output" >> "$AUDITCONFIG"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

if [ -e "/etc/audisp/plugins.d/au-remote.conf" ] ; then
    
    LC_ALL=C sed -i "/^\s*active\s*=\s*/Id" "/etc/audisp/plugins.d/au-remote.conf"
else
    touch "/etc/audisp/plugins.d/au-remote.conf"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/audisp/plugins.d/au-remote.conf"

cp "/etc/audisp/plugins.d/au-remote.conf" "/etc/audisp/plugins.d/au-remote.conf.bak"
# Insert at the end of the file
printf '%s\n' "active = yes" >> "/etc/audisp/plugins.d/au-remote.conf"
# Clean up after ourselves.
rm "/etc/audisp/plugins.d/au-remote.conf.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

if [ -e "/etc/audisp/plugins.d/au-remote.conf" ] ; then
    
    LC_ALL=C sed -i "/^\s*direction\s*=\s*/Id" "/etc/audisp/plugins.d/au-remote.conf"
else
    touch "/etc/audisp/plugins.d/au-remote.conf"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/audisp/plugins.d/au-remote.conf"

cp "/etc/audisp/plugins.d/au-remote.conf" "/etc/audisp/plugins.d/au-remote.conf.bak"
# Insert at the end of the file
printf '%s\n' "direction = out" >> "/etc/audisp/plugins.d/au-remote.conf"
# Clean up after ourselves.
rm "/etc/audisp/plugins.d/au-remote.conf.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

if [ -e "/etc/audisp/plugins.d/au-remote.conf" ] ; then
    
    LC_ALL=C sed -i "/^\s*path\s*=\s*/Id" "/etc/audisp/plugins.d/au-remote.conf"
else
    touch "/etc/audisp/plugins.d/au-remote.conf"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/audisp/plugins.d/au-remote.conf"

cp "/etc/audisp/plugins.d/au-remote.conf" "/etc/audisp/plugins.d/au-remote.conf.bak"
# Insert at the end of the file
printf '%s\n' "path = /sbin/audisp-remote" >> "/etc/audisp/plugins.d/au-remote.conf"
# Clean up after ourselves.
rm "/etc/audisp/plugins.d/au-remote.conf.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

if [ -e "/etc/audisp/plugins.d/au-remote.conf" ] ; then
    
    LC_ALL=C sed -i "/^\s*type\s*=\s*/Id" "/etc/audisp/plugins.d/au-remote.conf"
else
    touch "/etc/audisp/plugins.d/au-remote.conf"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/audisp/plugins.d/au-remote.conf"

cp "/etc/audisp/plugins.d/au-remote.conf" "/etc/audisp/plugins.d/au-remote.conf.bak"
# Insert at the end of the file
printf '%s\n' "type = always" >> "/etc/audisp/plugins.d/au-remote.conf"
# Clean up after ourselves.
rm "/etc/audisp/plugins.d/au-remote.conf.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

var_auditd_action_mail_acct='root'


AUDITCONFIG=/etc/audit/auditd.conf

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^action_mail_acct")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$var_auditd_action_mail_acct"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^action_mail_acct\\>" "$AUDITCONFIG"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^action_mail_acct\\>.*/$escaped_formatted_output/gi" "$AUDITCONFIG"
else
    if [[ -s "$AUDITCONFIG" ]] && [[ -n "$(tail -c 1 -- "$AUDITCONFIG" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "$AUDITCONFIG"
    fi
    cce="CCE-27394-6"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "$AUDITCONFIG" >> "$AUDITCONFIG"
    printf '%s\n' "$formatted_output" >> "$AUDITCONFIG"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi




# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

var_auditd_space_left_action='email'


#
# If space_left_action present in /etc/audit/auditd.conf, change value
# to var_auditd_space_left_action, else
# add "space_left_action = $var_auditd_space_left_action" to /etc/audit/auditd.conf
#

AUDITCONFIG=/etc/audit/auditd.conf

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^space_left_action")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$var_auditd_space_left_action"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^space_left_action\\>" "$AUDITCONFIG"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^space_left_action\\>.*/$escaped_formatted_output/gi" "$AUDITCONFIG"
else
    if [[ -s "$AUDITCONFIG" ]] && [[ -n "$(tail -c 1 -- "$AUDITCONFIG" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "$AUDITCONFIG"
    fi
    cce="CCE-27375-5"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "$AUDITCONFIG" >> "$AUDITCONFIG"
    printf '%s\n' "$formatted_output" >> "$AUDITCONFIG"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi




# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

var_auditd_space_left_percentage='25'


grep -q "^space_left[[:space:]]*=.*$" /etc/audit/auditd.conf && \
  sed -i "s/^space_left[[:space:]]*=.*$/space_left = $var_auditd_space_left_percentage%/g" /etc/audit/auditd.conf || \
  echo "space_left = $var_auditd_space_left_percentage%" >> /etc/audit/auditd.conf

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

if [ -e "/etc/audisp/audispd.conf" ] ; then
    
    LC_ALL=C sed -i "/^\s*name_format\s*=\s*/Id" "/etc/audisp/audispd.conf"
else
    touch "/etc/audisp/audispd.conf"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/audisp/audispd.conf"

cp "/etc/audisp/audispd.conf" "/etc/audisp/audispd.conf.bak"
# Insert at the end of the file
printf '%s\n' "name_format = hostname" >> "/etc/audisp/audispd.conf"
# Clean up after ourselves.
rm "/etc/audisp/audispd.conf.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q audit; then

if [ -e "/etc/audisp/audispd.conf" ] ; then
    
    LC_ALL=C sed -i "/^\s*overflow_action\s*=\s*/Id" "/etc/audisp/audispd.conf"
else
    touch "/etc/audisp/audispd.conf"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/audisp/audispd.conf"

cp "/etc/audisp/audispd.conf" "/etc/audisp/audispd.conf.bak"
# Insert at the end of the file
printf '%s\n' "overflow_action = syslog" >> "/etc/audisp/audispd.conf"
# Clean up after ourselves.
rm "/etc/audisp/audispd.conf.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && { rpm --quiet -q audit; }; then

SYSTEMCTL_EXEC='/usr/bin/systemctl'
"$SYSTEMCTL_EXEC" unmask 'auditd.service'
"$SYSTEMCTL_EXEC" start 'auditd.service'
"$SYSTEMCTL_EXEC" enable 'auditd.service'

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

if ! grep -s "^\s*cron\.\*\s*/var/log/cron$" /etc/rsyslog.conf /etc/rsyslog.d/*.conf; then
	mkdir -p /etc/rsyslog.d
	echo "cron.*	/var/log/cron" >> /etc/rsyslog.d/cron.conf
fi

systemctl restart rsyslog.service

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

legacy_regex='^\s*\$(((Input(TCP|RELP)|UDP)ServerRun)|ModLoad\s+(imtcp|imudp|imrelp))'
rainer_regex='^\s*(module|input)\((load|type)="(imtcp|imudp)".*$'

readarray -t legacy_targets < <(grep -l -E -r "${legacy_regex[@]}" /etc/rsyslog.conf /etc/rsyslog.d/)
readarray -t rainer_targets < <(grep -l -E -r "${rainer_regex[@]}" /etc/rsyslog.conf /etc/rsyslog.d/)

config_changed=false
if [ ${#legacy_targets[@]} -gt 0 ]; then
    for target in "${legacy_targets[@]}"; do
        sed -E -i "/$legacy_regex/ s/^/# /" "$target"
    done
    config_changed=true
fi

if [ ${#rainer_targets[@]} -gt 0 ]; then
    for target in "${rainer_targets[@]}"; do
        sed -E -i "/$rainer_regex/ s/^/# /" "$target"
    done
    config_changed=true
fi

if $config_changed; then
    systemctl restart rsyslog.service
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi




# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

rsyslog_remote_loghost_address='logcollector'


# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^\*\.\*")

# shellcheck disable=SC2059
printf -v formatted_output "%s %s" "$stripped_key" "@@$rsyslog_remote_loghost_address"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^\*\.\*\\>" "/etc/rsyslog.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^\*\.\*\\>.*/$escaped_formatted_output/gi" "/etc/rsyslog.conf"
else
    if [[ -s "/etc/rsyslog.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/rsyslog.conf" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/rsyslog.conf"
    fi
    cce="CCE-27343-3"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/rsyslog.conf" >> "/etc/rsyslog.conf"
    printf '%s\n' "$formatted_output" >> "/etc/rsyslog.conf"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

SYSTEMCTL_EXEC='/usr/bin/systemctl'
"$SYSTEMCTL_EXEC" unmask 'firewalld.service'
"$SYSTEMCTL_EXEC" start 'firewalld.service'
"$SYSTEMCTL_EXEC" enable 'firewalld.service'

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

# Comment out any occurrences of net.ipv6.conf.all.accept_source_route from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv6.conf.all.accept_source_route.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv6.conf.all.accept_source_route" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"

sysctl_net_ipv6_conf_all_accept_source_route_value='0'


#
# Set runtime for net.ipv6.conf.all.accept_source_route
#
/sbin/sysctl -q -n -w net.ipv6.conf.all.accept_source_route="$sysctl_net_ipv6_conf_all_accept_source_route_value"

#
# If net.ipv6.conf.all.accept_source_route present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv6.conf.all.accept_source_route = value" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv6.conf.all.accept_source_route")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv6_conf_all_accept_source_route_value"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv6.conf.all.accept_source_route\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv6.conf.all.accept_source_route\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    cce="CCE-80179-5"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "${SYSCONFIG_FILE}" >> "${SYSCONFIG_FILE}"
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

# Comment out any occurrences of net.ipv4.conf.all.accept_redirects from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.all.accept_redirects.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.all.accept_redirects" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"

sysctl_net_ipv4_conf_all_accept_redirects_value='0'


#
# Set runtime for net.ipv4.conf.all.accept_redirects
#
/sbin/sysctl -q -n -w net.ipv4.conf.all.accept_redirects="$sysctl_net_ipv4_conf_all_accept_redirects_value"

#
# If net.ipv4.conf.all.accept_redirects present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.conf.all.accept_redirects = value" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.conf.all.accept_redirects")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv4_conf_all_accept_redirects_value"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.conf.all.accept_redirects\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.conf.all.accept_redirects\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    cce="CCE-80158-9"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "${SYSCONFIG_FILE}" >> "${SYSCONFIG_FILE}"
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi





# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

# Comment out any occurrences of net.ipv4.conf.all.accept_source_route from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.all.accept_source_route.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.all.accept_source_route" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"

sysctl_net_ipv4_conf_all_accept_source_route_value='0'


#
# Set runtime for net.ipv4.conf.all.accept_source_route
#
/sbin/sysctl -q -n -w net.ipv4.conf.all.accept_source_route="$sysctl_net_ipv4_conf_all_accept_source_route_value"

#
# If net.ipv4.conf.all.accept_source_route present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.conf.all.accept_source_route = value" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.conf.all.accept_source_route")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv4_conf_all_accept_source_route_value"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.conf.all.accept_source_route\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.conf.all.accept_source_route\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    cce="CCE-27434-0"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "${SYSCONFIG_FILE}" >> "${SYSCONFIG_FILE}"
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi




# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

# Comment out any occurrences of net.ipv4.conf.all.rp_filter from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.all.rp_filter.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.all.rp_filter" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"

sysctl_net_ipv4_conf_all_rp_filter_value='1'


#
# Set runtime for net.ipv4.conf.all.rp_filter
#
/sbin/sysctl -q -n -w net.ipv4.conf.all.rp_filter="$sysctl_net_ipv4_conf_all_rp_filter_value"

#
# If net.ipv4.conf.all.rp_filter present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.conf.all.rp_filter = value" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.conf.all.rp_filter")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv4_conf_all_rp_filter_value"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.conf.all.rp_filter\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.conf.all.rp_filter\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    cce="CCE-80167-0"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "${SYSCONFIG_FILE}" >> "${SYSCONFIG_FILE}"
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi




# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

# Comment out any occurrences of net.ipv4.conf.default.accept_redirects from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.default.accept_redirects.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.default.accept_redirects" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"

sysctl_net_ipv4_conf_default_accept_redirects_value='0'


#
# Set runtime for net.ipv4.conf.default.accept_redirects
#
/sbin/sysctl -q -n -w net.ipv4.conf.default.accept_redirects="$sysctl_net_ipv4_conf_default_accept_redirects_value"

#
# If net.ipv4.conf.default.accept_redirects present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.conf.default.accept_redirects = value" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.conf.default.accept_redirects")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv4_conf_default_accept_redirects_value"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.conf.default.accept_redirects\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.conf.default.accept_redirects\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    cce="CCE-80163-9"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "${SYSCONFIG_FILE}" >> "${SYSCONFIG_FILE}"
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

# Comment out any occurrences of net.ipv4.conf.default.accept_source_route from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.default.accept_source_route.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.default.accept_source_route" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"

sysctl_net_ipv4_conf_default_accept_source_route_value='0'


#
# Set runtime for net.ipv4.conf.default.accept_source_route
#
/sbin/sysctl -q -n -w net.ipv4.conf.default.accept_source_route="$sysctl_net_ipv4_conf_default_accept_source_route_value"

#
# If net.ipv4.conf.default.accept_source_route present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.conf.default.accept_source_route = value" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.conf.default.accept_source_route")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv4_conf_default_accept_source_route_value"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.conf.default.accept_source_route\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.conf.default.accept_source_route\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    cce="CCE-80162-1"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "${SYSCONFIG_FILE}" >> "${SYSCONFIG_FILE}"
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi




# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

# Comment out any occurrences of net.ipv4.conf.default.rp_filter from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.default.rp_filter.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.default.rp_filter" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"

sysctl_net_ipv4_conf_default_rp_filter_value='1'


#
# Set runtime for net.ipv4.conf.default.rp_filter
#
/sbin/sysctl -q -n -w net.ipv4.conf.default.rp_filter="$sysctl_net_ipv4_conf_default_rp_filter_value"

#
# If net.ipv4.conf.default.rp_filter present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.conf.default.rp_filter = value" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.conf.default.rp_filter")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv4_conf_default_rp_filter_value"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.conf.default.rp_filter\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.conf.default.rp_filter\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    cce="CCE-80168-8"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "${SYSCONFIG_FILE}" >> "${SYSCONFIG_FILE}"
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

# Comment out any occurrences of net.ipv4.icmp_echo_ignore_broadcasts from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.icmp_echo_ignore_broadcasts.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.icmp_echo_ignore_broadcasts" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"

sysctl_net_ipv4_icmp_echo_ignore_broadcasts_value='1'


#
# Set runtime for net.ipv4.icmp_echo_ignore_broadcasts
#
/sbin/sysctl -q -n -w net.ipv4.icmp_echo_ignore_broadcasts="$sysctl_net_ipv4_icmp_echo_ignore_broadcasts_value"

#
# If net.ipv4.icmp_echo_ignore_broadcasts present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.icmp_echo_ignore_broadcasts = value" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.icmp_echo_ignore_broadcasts")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv4_icmp_echo_ignore_broadcasts_value"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.icmp_echo_ignore_broadcasts\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.icmp_echo_ignore_broadcasts\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    cce="CCE-80165-4"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "${SYSCONFIG_FILE}" >> "${SYSCONFIG_FILE}"
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

# Comment out any occurrences of net.ipv4.conf.all.send_redirects from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.all.send_redirects.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.all.send_redirects" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"


#
# Set runtime for net.ipv4.conf.all.send_redirects
#
/sbin/sysctl -q -n -w net.ipv4.conf.all.send_redirects="0"

#
# If net.ipv4.conf.all.send_redirects present in /etc/sysctl.conf, change value to "0"
#	else, add "net.ipv4.conf.all.send_redirects = 0" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.conf.all.send_redirects")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "0"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.conf.all.send_redirects\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.conf.all.send_redirects\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    cce="CCE-80156-3"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "${SYSCONFIG_FILE}" >> "${SYSCONFIG_FILE}"
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

# Comment out any occurrences of net.ipv4.conf.default.send_redirects from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.default.send_redirects.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.default.send_redirects" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"


#
# Set runtime for net.ipv4.conf.default.send_redirects
#
/sbin/sysctl -q -n -w net.ipv4.conf.default.send_redirects="0"

#
# If net.ipv4.conf.default.send_redirects present in /etc/sysctl.conf, change value to "0"
#	else, add "net.ipv4.conf.default.send_redirects = 0" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.conf.default.send_redirects")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "0"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.conf.default.send_redirects\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.conf.default.send_redirects\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    cce="CCE-80999-6"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "${SYSCONFIG_FILE}" >> "${SYSCONFIG_FILE}"
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi




# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

# Comment out any occurrences of net.ipv4.ip_forward from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.ip_forward.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.ip_forward" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"


#
# Set runtime for net.ipv4.ip_forward
#
/sbin/sysctl -q -n -w net.ipv4.ip_forward="0"

#
# If net.ipv4.ip_forward present in /etc/sysctl.conf, change value to "0"
#	else, add "net.ipv4.ip_forward = 0" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.ip_forward")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "0"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.ip_forward\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.ip_forward\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    cce="CCE-80157-1"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "${SYSCONFIG_FILE}" >> "${SYSCONFIG_FILE}"
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi




# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

if LC_ALL=C grep -q -m 1 "^install dccp" /etc/modprobe.d/dccp.conf ; then
	
	sed -i 's#^install dccp.*#install dccp /bin/true#g' /etc/modprobe.d/dccp.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/dccp.conf
	echo "install dccp /bin/true" >> /etc/modprobe.d/dccp.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist dccp$" /etc/modprobe.d/dccp.conf ; then
	echo "blacklist dccp" >> /etc/modprobe.d/dccp.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi


if ! rpm -q --quiet "NetworkManager" ; then
    dnf install -y "NetworkManager"
fi

nmcli radio all off


# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

SYSTEMCTL_EXEC='/usr/bin/systemctl'
"$SYSTEMCTL_EXEC" stop 'autofs.service'
"$SYSTEMCTL_EXEC" disable 'autofs.service'
"$SYSTEMCTL_EXEC" mask 'autofs.service'
# Disable socket activation if we have a unit file for it
if "$SYSTEMCTL_EXEC" -q list-unit-files autofs.socket; then
    "$SYSTEMCTL_EXEC" stop 'autofs.socket'
    "$SYSTEMCTL_EXEC" mask 'autofs.socket'
fi
# The service may not be running because it has been started and failed,
# so let's reset the state so OVAL checks pass.
# Service should be 'inactive', not 'failed' after reboot though.
"$SYSTEMCTL_EXEC" reset-failed 'autofs.service' || true

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

if LC_ALL=C grep -q -m 1 "^install usb-storage" /etc/modprobe.d/usb-storage.conf ; then
	
	sed -i 's#^install usb-storage.*#install usb-storage /bin/true#g' /etc/modprobe.d/usb-storage.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/usb-storage.conf
	echo "install usb-storage /bin/true" >> /etc/modprobe.d/usb-storage.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist usb-storage$" /etc/modprobe.d/usb-storage.conf ; then
	echo "blacklist usb-storage" >> /etc/modprobe.d/usb-storage.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

function perform_remediation {
    


    mount_point_match_regexp="$(printf "[[:space:]]%s[[:space:]]" /dev/shm)"

    # If the mount point is not in /etc/fstab, get previous mount options from /etc/mtab
    if ! grep "$mount_point_match_regexp" /etc/fstab; then
        # runtime opts without some automatic kernel/userspace-added defaults
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
                    | sed -E "s/(rw|defaults|seclabel|nodev)(,|$)//g;s/,$//")
        [ "$previous_mount_opts" ] && previous_mount_opts+=","
        echo "tmpfs /dev/shm tmpfs defaults,${previous_mount_opts}nodev 0 0" >> /etc/fstab
    # If the mount_opt option is not already in the mount point's /etc/fstab entry, add it
    elif ! grep "$mount_point_match_regexp" /etc/fstab | grep "nodev"; then
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/fstab | awk '{print $4}')
        sed -i "s|\(${mount_point_match_regexp}.*${previous_mount_opts}\)|\1,nodev|" /etc/fstab
    fi


    if mkdir -p "/dev/shm"; then
        if mountpoint -q "/dev/shm"; then
            mount -o remount --target "/dev/shm"
        fi
    fi
}

perform_remediation

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

function perform_remediation {
    


    mount_point_match_regexp="$(printf "[[:space:]]%s[[:space:]]" /dev/shm)"

    # If the mount point is not in /etc/fstab, get previous mount options from /etc/mtab
    if ! grep "$mount_point_match_regexp" /etc/fstab; then
        # runtime opts without some automatic kernel/userspace-added defaults
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
                    | sed -E "s/(rw|defaults|seclabel|noexec)(,|$)//g;s/,$//")
        [ "$previous_mount_opts" ] && previous_mount_opts+=","
        echo "tmpfs /dev/shm tmpfs defaults,${previous_mount_opts}noexec 0 0" >> /etc/fstab
    # If the mount_opt option is not already in the mount point's /etc/fstab entry, add it
    elif ! grep "$mount_point_match_regexp" /etc/fstab | grep "noexec"; then
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/fstab | awk '{print $4}')
        sed -i "s|\(${mount_point_match_regexp}.*${previous_mount_opts}\)|\1,noexec|" /etc/fstab
    fi


    if mkdir -p "/dev/shm"; then
        if mountpoint -q "/dev/shm"; then
            mount -o remount --target "/dev/shm"
        fi
    fi
}

perform_remediation

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

function perform_remediation {
    


    mount_point_match_regexp="$(printf "[[:space:]]%s[[:space:]]" /dev/shm)"

    # If the mount point is not in /etc/fstab, get previous mount options from /etc/mtab
    if ! grep "$mount_point_match_regexp" /etc/fstab; then
        # runtime opts without some automatic kernel/userspace-added defaults
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
                    | sed -E "s/(rw|defaults|seclabel|nosuid)(,|$)//g;s/,$//")
        [ "$previous_mount_opts" ] && previous_mount_opts+=","
        echo "tmpfs /dev/shm tmpfs defaults,${previous_mount_opts}nosuid 0 0" >> /etc/fstab
    # If the mount_opt option is not already in the mount point's /etc/fstab entry, add it
    elif ! grep "$mount_point_match_regexp" /etc/fstab | grep "nosuid"; then
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/fstab | awk '{print $4}')
        sed -i "s|\(${mount_point_match_regexp}.*${previous_mount_opts}\)|\1,nosuid|" /etc/fstab
    fi


    if mkdir -p "/dev/shm"; then
        if mountpoint -q "/dev/shm"; then
            mount -o remount --target "/dev/shm"
        fi
    fi
}

perform_remediation

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi




# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

function perform_remediation {
    
        mount_point_match_regexp="$(printf "[[:space:]]%s[[:space:]]" "/home")"

    grep "$mount_point_match_regexp" -q /etc/fstab \
        || { echo "The mount point '/home' is not even in /etc/fstab, so we can't set up mount options" >&2;
                echo "Not remediating, because there is no record of /home in /etc/fstab" >&2; return 1; }
    


    mount_point_match_regexp="$(printf "[[:space:]]%s[[:space:]]" /home)"

    # If the mount point is not in /etc/fstab, get previous mount options from /etc/mtab
    if ! grep "$mount_point_match_regexp" /etc/fstab; then
        # runtime opts without some automatic kernel/userspace-added defaults
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
                    | sed -E "s/(rw|defaults|seclabel|nosuid)(,|$)//g;s/,$//")
        [ "$previous_mount_opts" ] && previous_mount_opts+=","
        echo " /home  defaults,${previous_mount_opts}nosuid 0 0" >> /etc/fstab
    # If the mount_opt option is not already in the mount point's /etc/fstab entry, add it
    elif ! grep "$mount_point_match_regexp" /etc/fstab | grep "nosuid"; then
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/fstab | awk '{print $4}')
        sed -i "s|\(${mount_point_match_regexp}.*${previous_mount_opts}\)|\1,nosuid|" /etc/fstab
    fi


    if mkdir -p "/home"; then
        if mountpoint -q "/home"; then
            mount -o remount --target "/home"
        fi
    fi
}

perform_remediation

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

var_removable_partition='/dev/cdrom'


device_regex="^\s*$var_removable_partition\s\+"
mount_option="nosuid"

if grep -q $device_regex /etc/fstab ; then
    previous_opts=$(grep $device_regex /etc/fstab | awk '{print $4}')
    sed -i "s|\($device_regex.*$previous_opts\)|\1,$mount_option|" /etc/fstab
else
    echo "Not remediating, because there is no record of $var_removable_partition in /etc/fstab" >&2
    return 1
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi


# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

# Comment out any occurrences of kernel.randomize_va_space from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do

  matching_list=$(grep -P '^(?!#).*[\s]*kernel.randomize_va_space.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "kernel.randomize_va_space" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"


#
# Set runtime for kernel.randomize_va_space
#
/sbin/sysctl -q -n -w kernel.randomize_va_space="2"

#
# If kernel.randomize_va_space present in /etc/sysctl.conf, change value to "2"
#	else, add "kernel.randomize_va_space = 2" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^kernel.randomize_va_space")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "2"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^kernel.randomize_va_space\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^kernel.randomize_va_space\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    cce="CCE-27127-0"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "${SYSCONFIG_FILE}" >> "${SYSCONFIG_FILE}"
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

# Comment out any occurrences of kernel.dmesg_restrict from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do

  matching_list=$(grep -P '^(?!#).*[\s]*kernel.dmesg_restrict.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "kernel.dmesg_restrict" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"


#
# Set runtime for kernel.dmesg_restrict
#
/sbin/sysctl -q -n -w kernel.dmesg_restrict="1"

#
# If kernel.dmesg_restrict present in /etc/sysctl.conf, change value to "1"
#	else, add "kernel.dmesg_restrict = 1" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^kernel.dmesg_restrict")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "1"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^kernel.dmesg_restrict\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^kernel.dmesg_restrict\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    cce="CCE-27050-4"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "${SYSCONFIG_FILE}" >> "${SYSCONFIG_FILE}"
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if ! ( [ "${container:-}" == "bwrap-osbuild" ] ) && [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

var_ssh_sysadm_login='false'


setsebool -P ssh_sysadm_login $var_ssh_sysadm_login

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

var_selinux_policy_name='targeted'


if [ -e "/etc/selinux/config" ] ; then
    
    LC_ALL=C sed -i "/^SELINUXTYPE=/Id" "/etc/selinux/config"
else
    touch "/etc/selinux/config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/selinux/config"

cp "/etc/selinux/config" "/etc/selinux/config.bak"
# Insert at the end of the file
printf '%s\n' "SELINUXTYPE=$var_selinux_policy_name" >> "/etc/selinux/config"
# Clean up after ourselves.
rm "/etc/selinux/config.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

var_selinux_state='enforcing'


if [ -e "/etc/selinux/config" ] ; then
    
    LC_ALL=C sed -i "/^SELINUX=/Id" "/etc/selinux/config"
else
    touch "/etc/selinux/config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/selinux/config"

cp "/etc/selinux/config" "/etc/selinux/config.bak"
# Insert at the end of the file
printf '%s\n' "SELINUX=$var_selinux_state" >> "/etc/selinux/config"
# Clean up after ourselves.
rm "/etc/selinux/config.bak"

fixfiles onboot
fixfiles -f relabel

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

SYSTEMCTL_EXEC='/usr/bin/systemctl'
"$SYSTEMCTL_EXEC" stop 'kdump.service'
"$SYSTEMCTL_EXEC" disable 'kdump.service'
"$SYSTEMCTL_EXEC" mask 'kdump.service'
# Disable socket activation if we have a unit file for it
if "$SYSTEMCTL_EXEC" -q list-unit-files kdump.socket; then
    "$SYSTEMCTL_EXEC" stop 'kdump.socket'
    "$SYSTEMCTL_EXEC" mask 'kdump.socket'
fi
# The service may not be running because it has been started and failed,
# so let's reset the state so OVAL checks pass.
# Service should be 'inactive', not 'failed' after reboot though.
"$SYSTEMCTL_EXEC" reset-failed 'kdump.service' || true

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

chgrp 0 /etc/cron.allow

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

chown 0 /etc/cron.allow

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q postfix; then

if ! grep -q ^smtpd_client_restrictions /etc/postfix/main.cf; then
	echo "smtpd_client_restrictions = permit_mynetworks,reject" >> /etc/postfix/main.cf
else
	sed -i "s/^smtpd_client_restrictions.*/smtpd_client_restrictions = permit_mynetworks,reject/g" /etc/postfix/main.cf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

vfstype_points=()
readarray -t vfstype_points < <(grep -E "[[:space:]]nfs[4]?[[:space:]]" /etc/fstab | awk '{print $2}')

for vfstype_point in "${vfstype_points[@]}"
do
    mount_point_match_regexp="$(printf "[[:space:]]%s[[:space:]]" ${vfstype_point//\\/\\\\})"

    # If the mount point is not in /etc/fstab, get previous mount options from /etc/mtab
    if ! grep "$mount_point_match_regexp" /etc/fstab; then
        # runtime opts without some automatic kernel/userspace-added defaults
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
                    | sed -E "s/(rw|defaults|seclabel|sec=krb5:krb5i:krb5p)(,|$)//g;s/,$//")
        [ "$previous_mount_opts" ] && previous_mount_opts+=","
        echo " ${vfstype_point//\\/\\\\} nfs4 defaults,${previous_mount_opts}sec=krb5:krb5i:krb5p 0 0" >> /etc/fstab
    # If the mount_opt option is not already in the mount point's /etc/fstab entry, add it
    elif ! grep "$mount_point_match_regexp" /etc/fstab | grep "sec=krb5:krb5i:krb5p"; then
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/fstab | awk '{print $4}')
        sed -i "s|\(${mount_point_match_regexp}.*${previous_mount_opts}\)|\1,sec=krb5:krb5i:krb5p|" /etc/fstab
    fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

vfstype_points=()
readarray -t vfstype_points < <(grep -E "[[:space:]]nfs[4]?[[:space:]]" /etc/fstab | awk '{print $2}')

for vfstype_point in "${vfstype_points[@]}"
do
    mount_point_match_regexp="$(printf "[[:space:]]%s[[:space:]]" ${vfstype_point//\\/\\\\})"

    # If the mount point is not in /etc/fstab, get previous mount options from /etc/mtab
    if ! grep "$mount_point_match_regexp" /etc/fstab; then
        # runtime opts without some automatic kernel/userspace-added defaults
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
                    | sed -E "s/(rw|defaults|seclabel|noexec)(,|$)//g;s/,$//")
        [ "$previous_mount_opts" ] && previous_mount_opts+=","
        echo " ${vfstype_point//\\/\\\\} nfs4 defaults,${previous_mount_opts}noexec 0 0" >> /etc/fstab
    # If the mount_opt option is not already in the mount point's /etc/fstab entry, add it
    elif ! grep "$mount_point_match_regexp" /etc/fstab | grep "noexec"; then
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/fstab | awk '{print $4}')
        sed -i "s|\(${mount_point_match_regexp}.*${previous_mount_opts}\)|\1,noexec|" /etc/fstab
    fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

vfstype_points=()
readarray -t vfstype_points < <(grep -E "[[:space:]]nfs[4]?[[:space:]]" /etc/fstab | awk '{print $2}')

for vfstype_point in "${vfstype_points[@]}"
do
    mount_point_match_regexp="$(printf "[[:space:]]%s[[:space:]]" ${vfstype_point//\\/\\\\})"

    # If the mount point is not in /etc/fstab, get previous mount options from /etc/mtab
    if ! grep "$mount_point_match_regexp" /etc/fstab; then
        # runtime opts without some automatic kernel/userspace-added defaults
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
                    | sed -E "s/(rw|defaults|seclabel|nosuid)(,|$)//g;s/,$//")
        [ "$previous_mount_opts" ] && previous_mount_opts+=","
        echo " ${vfstype_point//\\/\\\\} nfs4 defaults,${previous_mount_opts}nosuid 0 0" >> /etc/fstab
    # If the mount_opt option is not already in the mount point's /etc/fstab entry, add it
    elif ! grep "$mount_point_match_regexp" /etc/fstab | grep "nosuid"; then
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/fstab | awk '{print $4}')
        sed -i "s|\(${mount_point_match_regexp}.*${previous_mount_opts}\)|\1,nosuid|" /etc/fstab
    fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi




# Identify local mounts
MOUNT_LIST=$(df --local | awk '{ print $6 }')

# Find file on each listed mount point
for cur_mount in ${MOUNT_LIST}
do
	find ${cur_mount} -xdev -type f -name "shosts.equiv" -exec rm -f {} \;
done



# Identify local mounts
MOUNT_LIST=$(df --local | awk '{ print $6 }')

# Find file on each listed mount point
for cur_mount in ${MOUNT_LIST}
do
	find ${cur_mount} -xdev -type f -name ".shosts" -exec rm -f {} \;
done



# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q sssd-common; then

var_sssd_ldap_tls_ca_dir='/etc/openldap/cacerts'


SSSD_CONF="/etc/sssd/sssd.conf"
LDAP_REGEX='[[:space:]]*\[domain\/[^]]*]([^(\n)]*(\n)+)+?[[:space:]]*ldap_tls_cacertdir'
AD_REGEX='[[:space:]]*\[domain\/[^]]*]([^(\n)]*(\n)+)+?[[:space:]]*id_provider[[:space:]]*=[[:space:]]*((?i)ad)[[:space:]]*$'
DOMAIN_REGEX="[[:space:]]*\[domain\/[^]]*]"

# Check if id_provider is not set to ad (Active Directory) which makes start_tls not applicable, note the -v option to invert the grep.
# Try to find [domain/..] and ldap_tls_cacertdir in sssd.conf, if it exists, set to '$var_sssd_ldap_tls_ca_dir'
# if ldap_tls_cacertdir isn't here, add it
# if [domain/..] doesn't exist, add it here for default domain
if grep -qvzosP $AD_REGEX $SSSD_CONF; then
        if grep -qzosP $LDAP_REGEX $SSSD_CONF; then
                
                sed -i "s#ldap_tls_cacertdir[^(\n)]*#ldap_tls_cacertdir = $var_sssd_ldap_tls_ca_dir#" $SSSD_CONF
        elif grep -qs $DOMAIN_REGEX $SSSD_CONF; then
                sed -i "/$DOMAIN_REGEX/a ldap_tls_cacertdir = $var_sssd_ldap_tls_ca_dir" $SSSD_CONF
        else
                if test -f "$SSSD_CONF"; then
                        echo -e "[domain/default]\nldap_tls_cacertdir = $var_sssd_ldap_tls_ca_dir" >> $SSSD_CONF
                else
                        echo "Config file '$SSSD_CONF' doesnt exist, not remediating, assuming non-applicability." >&2
                fi
        fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi


# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q sssd-common; then

SSSD_CONF="/etc/sssd/sssd.conf"
LDAP_REGEX='[[:space:]]*\[domain\/[^]]*]([^(\n)]*(\n)+)+?[[:space:]]*ldap_tls_reqcert'
AD_REGEX='[[:space:]]*\[domain\/[^]]*]([^(\n)]*(\n)+)+?[[:space:]]*id_provider[[:space:]]*=[[:space:]]*((?i)ad)[[:space:]]*$'
DOMAIN_REGEX="[[:space:]]*\[domain\/[^]]*]"

# Check if id_provider is not set to ad (Active Directory) which makes start_tls not applicable, note the -v option to invert the grep.
# Try to find [domain/..] and ldap_tls_reqcert in sssd.conf, if it exists, set to 'demand'
# if ldap_tls_reqcert isn't here, add it
# if [domain/..] doesn't exist, add it here for default domain
if grep -qvzosP $AD_REGEX $SSSD_CONF; then
        if grep -qzosP $LDAP_REGEX $SSSD_CONF; then
                
                sed -i "s#ldap_tls_reqcert[^(\n)]*#ldap_tls_reqcert = demand#" $SSSD_CONF
        elif grep -qs $DOMAIN_REGEX $SSSD_CONF; then
                sed -i "/$DOMAIN_REGEX/a ldap_tls_reqcert = demand" $SSSD_CONF
        else
                if test -f "$SSSD_CONF"; then
                        echo -e "[domain/default]\nldap_tls_reqcert = demand" >> $SSSD_CONF
                else
                        echo "Config file '$SSSD_CONF' doesnt exist, not remediating, assuming non-applicability." >&2
                fi
        fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi


# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && rpm --quiet -q sssd-common; then

SSSD_CONF="/etc/sssd/sssd.conf"
LDAP_REGEX='[[:space:]]*\[domain\/[^]]*]([^(\n)]*(\n)+)+?[[:space:]]*ldap_id_use_start_tls'
AD_REGEX='[[:space:]]*\[domain\/[^]]*]([^(\n)]*(\n)+)+?[[:space:]]*id_provider[[:space:]]*=[[:space:]]*((?i)ad)[[:space:]]*$'
DOMAIN_REGEX="[[:space:]]*\[domain\/[^]]*]"

# Check if id_provider is not set to ad (Active Directory) which makes start_tls not applicable, note the -v option to invert the grep.
# Try to find [domain/..] and ldap_id_use_start_tls in sssd.conf, if it exists, set to 'true'
# if ldap_id_use_start_tls isn't here, add it
# if [domain/..] doesn't exist, add it here for default domain
if grep -qvzosP $AD_REGEX $SSSD_CONF; then
        if grep -qzosP $LDAP_REGEX $SSSD_CONF; then
                
                sed -i "s#ldap_id_use_start_tls[^(\n)]*#ldap_id_use_start_tls = true#" $SSSD_CONF
        elif grep -qs $DOMAIN_REGEX $SSSD_CONF; then
                sed -i "/$DOMAIN_REGEX/a ldap_id_use_start_tls = true" $SSSD_CONF
        else
                if test -f "$SSSD_CONF"; then
                        echo -e "[domain/default]\nldap_id_use_start_tls = true" >> $SSSD_CONF
                else
                        echo "Config file '$SSSD_CONF' doesnt exist, not remediating, assuming non-applicability." >&2
                fi
        fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi


# Remediation is applicable only in certain platforms
if rpm --quiet -q sssd-common; then

SSSD_CONF="/etc/sssd/sssd.conf"
SSSD_CONF_DIR="/etc/sssd/conf.d/*.conf"

if [ ! -f "$SSSD_CONF" ] && [ ! -f "$SSSD_CONF_DIR" ]; then
    mkdir -p /etc/sssd
    touch "$SSSD_CONF"
fi

# Flag to check if there is already services with pam
service_already_exist=false
for f in $SSSD_CONF $SSSD_CONF_DIR; do
	if [ ! -e "$f" ]; then
		continue
	fi
	# finds all services entries under [sssd] configuration category, get a unique list so it doesn't add redundant fix
	services_list=$( awk '/^\s*\[/{f=0} /^\s*\[sssd\]/{f=1}f' $f | grep -P '^services[ \t]*=' | uniq )
    if [ -z "$services_list" ]; then
        continue
    fi

	while IFS= read -r services; do
		if [[ ! $services =~ "pam" ]]; then
			sed -i "s/$services$/&, pam/" $f
		fi
        # Either pam service was already there or got added now
        service_already_exist=true
	done <<< "$services_list"

done

# If there was no service in [sssd], add it to first config
if [ "$service_already_exist" = false ]; then
    for f in $SSSD_CONF $SSSD_CONF_DIR; do
        cat << EOF >> "$f"
[sssd]
services = pam
EOF
        break
    done
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

echo "tmpfs /tmp tmpfs defaults,nosuid,nodev,noexec 0 0" >> /etc/fstab

