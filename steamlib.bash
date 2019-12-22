# A set of functions for interaction with the Steam web frontend
# 

# Wrapper for verbose exiting
function errexit(){
	echo "Error: $1"
	exit 1
}

# Be ready to clean up all the temp files we're going to create:
function cleanup(){
    rm -f "$CURLTMP"
    rm -f "$ASN1TMP"
    rm -f "$DERTMP"
    rm -f "$PEMTMP"
    rm -f "$RSATMP"
}
trap cleanup INT QUIT TERM EXIT

# Now create the temp files
CURLTMP="$(mktemp)"
ASN1TMP="$(mktemp)"
DERTMP="$(mktemp)"
PEMTMP="$(mktemp)"
RSATMP="$(mktemp)"

# Check for availability of external prerequisites
[[ -x "$(command -v curl)" ]] || errexit "curl is required but not installed"
[[ -x "$(command -v jq)" ]] || errexit "jq is required but not installed"
[[ -x "$(command -v openssl)" ]] || errexit "openssl is required but not installed"

# Curl cookie storage
COOKIEJAR=~/.cookiejar.steam
CURL="curl --progress-bar --cookie-jar $COOKIEJAR --cookie $COOKIEJAR"

function steam_check_login_status(){
	# Test whether we're already logged in.
	# Permalink to own profile found at:
	# https://www.reddit.com/r/Steam/comments/30kvjt/link_that_brings_you_to_your_own_profile/
	LOCATION=$($CURL -o/dev/null -w '%{redirect_url}' https://steamcommunity.com/my/profile)
	# If we get redirected to a login page, we aren't already logged in.
	if [[ "$LOCATION" =~ https://steamcommunity.com/id/(.*)/profile ]]
	then
		STEAM_PROFILEURL="$LOCATION"
		STEAM_VANITYURL="${BASH_REMATCH[1]}"
		STEAMLIB_STATUS="already logged in"
		steam_get_apikey
		steam_get_steamid
		steam_get_sessionid
		return 0
	else
		STEAMLIB_STATUS="not logged in"
		return 1
	fi
}

function steam_login(){
	# User and password may be supplied as environment variables
	if [[ ! -v STEAMUSER ]] 
	then
		read -p "Steam Username: " STEAMUSER || errexit "No user"
	fi
	STEAMLIB_STATUS='got STEAMUSER'
	if [[ ! -v STEAMPASS ]] 
	then
		read -p "Steam Password: " -s STEAMPASS || errexit "No password"
	fi
	STEAMLIB_STATUS='got STEAMPASS'

	# Get the RSA key that will be used to encrypt the password
	$CURL 'https://steamcommunity.com/login/getrsakey/' \
		--form "username=$STEAMUSER" \
		> "$CURLTMP" || errexit 'curl_rsakey'

	SUCCESS="$(jq --raw-output '.success' < "$CURLTMP")"
	if [[ ! "$SUCCESS" == 'true' ]]
	then
		errexit 'get rsakey'
	fi

	# Encryption requires modulus and exponent,
	# login requires the timestamp that was received.
	MOD="$(jq --raw-output '.publickey_mod' < "$CURLTMP")"
	EXP="$(jq --raw-output '.publickey_exp' < "$CURLTMP")"
	TIME="$(jq --raw-output '.timestamp' < "$CURLTMP")"
	STEAMLIB_STATUS='got RSA key'

	# Generate an RSA public key from modulus and exponent 
	# by providing an ASN1 description file.
	# https://stackoverflow.com/a/36448243/263310
	cat >>"$ASN1TMP" <<-End
	# Start with a SEQUENCE
	asn1=SEQUENCE:pubkeyinfo

	# pubkeyinfo contains an algorithm identifier and the public key wrapped
	# in a BIT STRING
	[pubkeyinfo]
	algorithm=SEQUENCE:rsa_alg
	pubkey=BITWRAP,SEQUENCE:rsapubkey

	# algorithm ID for RSA is just an OID and a NULL
	[rsa_alg]
	algorithm=OID:rsaEncryption
	parameter=NULL

	# Actual public key: modulus and exponent
	[rsapubkey]
	n=INTEGER:0x$MOD

	e=INTEGER:0x$EXP
	End

	# Generate an actual public key from ASN1, DER only.
	openssl asn1parse -genconf "$ASN1TMP" -out "$DERTMP" -noout || errexit 'asnparse'
	# Convert to PEM because this is how I roll
	openssl rsa -in "$DERTMP" -inform der -pubin -out "$PEMTMP" 2>/dev/null || errexit 'rsa'
	# Encrypt the password
	echo -n "$STEAMPASS" | openssl rsautl -encrypt -pkcs -inkey "$PEMTMP" -pubin > "$RSATMP" || errexit 'rsautl'
	# Encode the encrypted password as b64, remove linebreaks
	CRYPTPW="$(openssl base64 < "$RSATMP" | tr -d '\n')" || errexit 'base64'
	STEAMLIB_STATUS='encrypted password'

	# Log in using user name and password
	$CURL 'https://steamcommunity.com/login/dologin/' \
		--data-urlencode "username=$STEAMUSER" \
		--data-urlencode "password=$CRYPTPW" \
		--data-urlencode "twofactorcode=" \
		--data-urlencode "rsatimestamp=$TIME" \
		--data-urlencode "remember_login=true" > "$CURLTMP" || errexit 'curl_pre_2fa'

	# Steam should now return a request for two factor authentication
	# We could simply ask the user for 2FA and submit it, but then they
	# wouldn't get the popup on their mobile phone.
	#
	# If Steam asks for a CAPTCHA, you've been recognized 
	# as being a machine and the world has officially ended.
	CAPTCHA="$(jq --raw-output '.captcha_needed' < "$CURLTMP")"
	REQ2FA="$(jq --raw-output '.requires_twofactor' < "$CURLTMP")"
	if [[ "$CAPTCHA" == 'true' ]]
	then
		errexit 'response_steam_wants_captcha'
	fi
	if [[ ! "$REQ2FA" == 'true' ]]
	then
		errexit 'response_pre_2fa'
	fi
	STEAMLIB_STATUS="pre-2fa"

	# Ask for 2FA token and resubmit same request as above.
	read -p "Steam 2-factor token: " STEAM2FATOKEN
	$CURL 'https://steamcommunity.com/login/dologin/' \
		--data-urlencode "username=$STEAMUSER" \
		--data-urlencode "password=$CRYPTPW" \
		--data-urlencode "twofactorcode=$STEAM2FATOKEN" \
		--data-urlencode "rsatimestamp=$TIME" \
		--data-urlencode "remember_login=true" > "$CURLTMP" || errexit 'curl_post_2fa'
	STEAMLIB_STATUS="post-2fa"

	# Final check for completed login.
	LOGIN=$(jq --raw-output '.login_complete' < "$CURLTMP")
	if [[ "$LOGIN" == 'true' ]]
	then
		steam_get_apikey
		steam_get_steamid
		steam_get_sessionid
		STEAMLIB_STATUS="logged in with 2fa"
		return 0
	else
		errexit 'not logged in after attempted 2fa'
	fi
}

function steam_get_sessionid(){
	# Acquire the session cookie
	local THECOOKIE
	while read -r -a THECOOKIE
	do
		if [[ ${THECOOKIE[0]} == 'steamcommunity.com' && ${THECOOKIE[5]} == 'sessionid' ]]
		then
			STEAM_SESSIONID="${THECOOKIE[6]}"
		fi
	done < "$COOKIEJAR"
	if [[ ! -v STEAM_SESSIONID ]]
	then
		errexit 'No steamcommunity.com session id in cookie jar.'
	fi
}

function steam_set_nickname(){
	if [[ -z "$1" ]]
	then
		errexit "provide new nickname"
	else
		NEWNICK="$1"
	fi
}

function steam_get_apikey(){
	# Get Steam API key
	$CURL 'https://steamcommunity.com/dev/apikey' > "$CURLTMP" || errexit 'curl_apikey'

	local APIKEY_RE='Key: ([a-fA-F0-9][a-fA-F0-9]*)'
	local THELINE
	while read -r THELINE
	do
		if [[ "$THELINE" =~ $APIKEY_RE ]]
		then
			STEAM_APIKEY="${BASH_REMATCH[1]}"
			STEAMLIB_STATUS="Got API key: $STEAM_APIKEY"
			break
		fi
	done < "$CURLTMP"

	if [[ ! -v STEAM_APIKEY ]]
	then
		errexit 'No API key could be retrieved.'
	fi
}

function steam_get_steamid(){
	if [[ ! -v STEAM_APIKEY ]]
	then
		errexit 'call steam_get_apikey or set STEAM_APIKEY before calling steam_get_steamid'
	fi
	# Get numeric Steam ID for profile using the API key
	$CURL "https://api.steampowered.com/ISteamUser/ResolveVanityURL/v0001/?key=${STEAM_APIKEY}&vanityurl=${STEAM_VANITYURL}" \
		> "$CURLTMP" || errexit "curl_steamid"

	STEAM_STEAMID=$(jq --raw-output '.response.steamid' < "$CURLTMP")
}

function steam_set_nickname() {
	if [[ ! -v STEAM_SESSIONID ]]
	then
		errexit 'call steam_get_sessionid or set STEAM_SESSIONID before calling steam_set_nickname'
	fi
	if [[ ! -v STEAM_STEAMID ]]
	then
		errexit 'call steam_get_steamid or set STEAM_STEAMID before calling steam_set_nickname'
	fi
	if [[ -z "$1" ]]
	then
		errexit "provide new nickname"
	else
		NEWNICK="$1"
	fi
	$CURL "https://steamcommunity.com/profiles/${STEAM_STEAMID}/ajaxsetpersonaname/" \
		--form "persona=$NEWNICK" \
		--form "sessionid=$STEAM_SESSIONID" \
		> "$CURLTMP" && return 0 || errexit 'set_name'
}

