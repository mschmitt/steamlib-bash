#!/bin/bash

. $(dirname $(readlink -f $0))/steamlib.bash
steam_check_login_status || steam_login
steam_set_avatar "$1"
