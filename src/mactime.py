#!/usr/bin/env python3
#
# mactime.py - A Python reimplementation of mactime.pl from The Sleuth Kit®.
# This program is a Python port of the original mactime.pl code, which was written in Perl.
# The modified portions are provided under the terms of the Common Public License 1.0 (CPL 1.0).
# Modified by: S.Nakano
#
# This program is based on the 'mactime' program by Dan Farmer and
# and the 'mac_daddy' program by Rob Lee.
#
# It takes as input data from either 'ils -m' or 'fls -m' (from The Sleuth
# Kit) or 'mac-robber'.
# Based on the dates as arguments given, the data is sorted by and
# printed.
#
# The Sleuth Kit
# Brian Carrier [carrier <at> sleuthkit [dot] org]
# Copyright (c) 2003-2012 Brian Carrier.  All rights reserved
#
# TASK
# Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
#
#
# The modifications to the original mactime are distributed under
# the Common Public License 1.0
#
#
# Copyright 1999 by Dan Farmer.  All rights reserved.  Some individual
# files may be covered by other copyrights (this will be noted in the
# file itself.)
#
# Redistribution and use in source and binary forms are permitted
# provided that this entire copyright notice is duplicated in all such
# copies.
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR ANY PARTICULAR PURPOSE.
#
# IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, LOSS OF USE, DATA, OR PROFITS OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

import sys
import os
import time
import re
import argparse
from datetime import datetime, timezone


try:
    import pytz
except ImportError:
    pytz = None

sys.stdout.reconfigure(encoding='shiftjis')
encoding_format = "shiftjis"

VERSION: str = "1.0.0"
debug: int = 0

digit_to_month: dict[str, str] = {
    "01": "Jan",
    "02": "Feb",
    "03": "Mar",
    "04": "Apr",
    "05": "May",
    "06": "Jun",
    "07": "Jul",
    "08": "Aug",
    "09": "Sep",
    "10": "Oct",
    "11": "Nov",
    "12": "Dec"
}

digit_to_day: dict[str, str] = {
    "0": "Sun",
    "1": "Mon",
    "2": "Tue",
    "3": "Wed",
    "4": "Thu",
    "5": "Fri",
    "6": "Sat"
}


def usage() -> None:
    print("""
mactime.py [-b body_file] [-p password_file] [-g group_file] [-i day|hour idx_file] [-d] [-h] [-V] [-y] [-z TIME_ZONE] [DATE]
        -b: Specifies the body file location, else STDIN is used
        -d: Output in comma delimited format
        -h: Display a header with session information
        -i [day | hour] file: Specifies the index file with a summary of results
        -y: Dates are displayed in ISO 8601 format
        -m: Dates have month as number instead of word (does not work with -y)
        -z: Specify the timezone the data came from (in the local system format) (does not work with -y)
        -g: Specifies the group file location, else GIDs are used
        -p: Specifies the password file location, else UIDs are used
        -V: Prints the version to STDOUT
        [DATE]: starting date (yyyy-mm-dd) or range (yyyy-mm-dd..yyyy-mm-dd) 
        [DATE]: date with time (yyyy-mm-ddThh:mm:ss), using with range one or both can have time
    """)
    sys.exit(1)


def print_version() -> None:
    print(f"The Sleuth Kit ver {VERSION}")


BODY: str = ""
GROUP: str = ""
PASSWD: str = ""
TIME: str = ""
INDEX: str = ""
INDEX_DAY: int = 1
INDEX_HOUR: int = 2
INDEX_TYPE: int = INDEX_DAY
COMMA: int = 0

iso8601: bool = False
month_num: bool = False
header: bool = False

in_seconds: int = 0
out_seconds: int = 0
timestr2macstr: dict[str, str] = {}
file2other: dict[str, str] = {}

gid2names: dict[str, str] = {}
uid2names: dict[str, str] = {}

def get_timezone_list() -> list[str]:
    if pytz:
        return sorted(pytz.all_timezones)
    return []


def tm_split(line: str) -> list[str]:
    fields = line.split('|')
    for i in range(len(fields)):
        fields[i] = re.sub(r'%([A-F0-9]{2})',
                           lambda x: chr(int(x.group(1), 16)),
                           fields[i])
    return fields


def parse_isodate(iso_date: str) -> int:
    try:
        if re.match(r'^\d{4}-\d{2}-\d{2}$', iso_date):
            dt = datetime.strptime(iso_date, "%Y-%m-%d")
            return int(dt.timestamp())
        elif re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$', iso_date):
            dt = datetime.strptime(iso_date, "%Y-%m-%dT%H:%M:%S")
            return int(dt.timestamp())
        else:
            return -1
    except ValueError:
        return -1


def read_body() -> None:
    global in_seconds, out_seconds
    if BODY:
        try:
            with open(BODY, "r", encoding=encoding_format) as body_file:
                lines = body_file.readlines()
        except Exception as e:
            print(f"Can't open {BODY}: {e}")
            sys.exit(1)
    else:
        lines = sys.stdin.readlines()

    for line in lines:
        line = line.strip()
        if line.startswith('#') or not line:
            continue

        fields = tm_split(line)
        if len(fields) < 11:
            continue

        tmp1, file_name, st_ino, st_ls, st_uid, st_gid, st_size, st_atime, st_mtime, st_ctime, st_crtime = fields[:11]

        if not (st_ino and re.match(r'[\d-]+', st_ino)):
            continue
        if not (st_uid and re.match(r'\d+', st_uid)):
            continue
        if not (st_gid and re.match(r'\d+', st_gid)):
            continue
        if not (st_size and re.match(r'\d+', st_size)):
            continue
        if not (st_mtime and re.match(r'\d+', st_mtime)):
            continue
        if not (st_atime and re.match(r'\d+', st_atime)):
            continue
        if not (st_ctime and re.match(r'\d+', st_ctime)):
            continue
        if not (st_crtime and re.match(r'\d+', st_crtime)):
            continue

        if not (int(st_atime) or int(st_mtime) or int(st_ctime) or int(st_crtime)):
            continue

        if (int(st_mtime) < in_seconds and 
            int(st_atime) < in_seconds and 
            int(st_ctime) < in_seconds and 
            int(st_crtime) < in_seconds):
            continue

        post = f",{st_ino},{file_name}"

        timestamps = {
            "m": int(st_mtime),
            "a": int(st_atime),
            "c": int(st_ctime),
            "b": int(st_crtime)
        }
        for flag, ts in timestamps.items():
            padded = f"{ts:010d}"
            key = f"{padded}{post}"
            if ts >= in_seconds and (not out_seconds or ts < out_seconds):
                if flag not in timestr2macstr.get(key, ""):
                    timestr2macstr.setdefault(key, "")
                    timestr2macstr[key] += flag

        if st_uid not in uid2names:
            uid2names[st_uid] = st_uid
        if st_gid not in gid2names:
            gid2names[st_gid] = st_gid

        uid2names[st_uid] = uid2names[st_uid].replace(' ', '/')
        gid2names[st_gid] = gid2names[st_gid].replace(' ', '/')

        file2other[file_name] = f"{st_ls}:{uid2names[st_uid]}:{gid2names[st_gid]}:{st_size}"


def print_header() -> None:
    if not header:
        return

    print("The Sleuth Kit mactime Timeline")
    print("Input Source: ", end="")
    if BODY == "":
        print("STDIN")
    else:
        print(BODY)

    if TIME != "":
        print(f"Time: {TIME}\t\t", end="")

    if os.environ.get('TZ', '') == "":
        print()
    else:
        print(f"Timezone: {os.environ.get('TZ')}")

    if PASSWD != "":
        print(f"passwd File: {PASSWD}", end="")
    if GROUP != "":
        if PASSWD != "":
            print("\t", end="")
        print(f"group File: {GROUP}", end="")
    if PASSWD != "" or GROUP != "":
        print()
    print()


def print_tl() -> None:
    prev_day = ""
    prev_hour = ""
    prev_time = 0
    prev_cnt = 0
    old_date_string = ""
    delim = ":" if COMMA == 0 else ","
    if COMMA != 0:
        print("Date,Size,Type,Mode,UID,GID,Meta,File Name")

    for key in sorted(timestr2macstr.keys()):
        match = re.match(r'^(\d+),([\d-]+),(.*)$', key)
        if not match:
            continue

        time_val_str, inode, file_name = match.groups()
        time_val = int(time_val_str)

        if iso8601:
            t = datetime.fromtimestamp(time_val, tz=timezone.utc)
            sec, minute, hour = t.second, t.minute, t.hour
            mday, mon, year = t.day, t.month, t.year
            wday = (t.weekday() + 1) % 7
        else:
            t = time.localtime(time_val)
            sec, minute, hour = t.tm_sec, t.tm_min, t.tm_hour
            mday, mon, year = t.tm_mday, t.tm_mon, t.tm_year + 1900
            wday = t.tm_wday

        date_string = format_date_string(time_val, wday, mon, mday, year, hour, minute, sec)

        if old_date_string == date_string:
            date_string = " " * (20 if iso8601 else 24)
            if INDEX:
                prev_cnt += 1
        else:
            old_date_string = date_string
            if INDEX:
                current_day = f"{f'{mday:02d}'} {wday} {f'{mon:02d}'} {year}"
                current_hour = f"{hour:02d}"
                if not prev_day:
                    prev_day, prev_hour, prev_time, prev_cnt = current_day, current_hour, time_val, 0
                elif prev_day != current_day:
                    write_index_record(prev_day, prev_hour, prev_time, prev_cnt, delim)
                    prev_day, prev_hour, prev_time, prev_cnt = current_day, current_hour, time_val, 0
                elif INDEX_TYPE == INDEX_HOUR and prev_hour != current_hour:
                    write_index_record(prev_day, prev_hour, prev_time, prev_cnt, delim)
                    prev_hour, prev_time, prev_cnt = current_hour, time_val, 0
                prev_cnt += 1

        mactime_tmp = timestr2macstr[key]
        mactime = ("m" if "m" in mactime_tmp else ".") + \
                  ("a" if "a" in mactime_tmp else ".") + \
                  ("c" if "c" in mactime_tmp else ".") + \
                  ("b" if "b" in mactime_tmp else ".")

        ls, uids, groups, size = file2other[file_name].split(":")
        if debug:
            print(f"FILE: {file_name} MODES: {ls} U: {uids} G: {groups} S: {size}")
        if COMMA == 0:
            print(f"{date_string} {size:>8s} {mactime:3s} {ls} {uids:<8s} {groups:<8s} {inode:<8s} {file_name}")
        else:
            file_tmp = file_name.replace('\"', '""')
            print(f"{old_date_string},{size},{mactime},{ls},{uids},{groups},{inode},\"{file_tmp}\"")

    if INDEX and prev_cnt > 0:
        write_index_record(prev_day, prev_hour, prev_time, prev_cnt, delim)


passwd_loaded: bool = False
group_loaded: bool = False


def add_pw_info(name: str, *args: str) -> None:
    if name and len(args) >= 2:
        uid = args[1]
        if uid:
            if uid in uid2names:
                uid2names[uid] += f" {name}"
            else:
                uid2names[uid] = name


def add_gr_info(name: str, *args: str) -> None:
    if name and len(args) >= 2:
        gid = args[1]
        if gid:
            if gid in gid2names:
                gid2names[gid] += f" {name}"
            else:
                gid2names[gid] = name


def load_passwd_info(file_name: str) -> None:
    global passwd_loaded
    if passwd_loaded:
        return

    passwd_loaded = True
    try:
        with open(file_name, 'r', encoding=encoding_format) as file:
            for line in file:
                line = line.strip()
                if not line.startswith('+'):
                    add_pw_info(*line.split(':'))
    except Exception as e:
        print(f"Can't open {file_name}: {e}")
        sys.exit(1)


def load_group_info(file_name: str) -> None:
    global group_loaded
    if group_loaded:
        return

    group_loaded = True
    try:
        with open(file_name, 'r', encoding=encoding_format) as file:
            for line in file:
                line = line.strip()
                if not line.startswith('+'):
                    add_gr_info(*line.split(':'))
    except Exception as e:
        print(f"Can't open {file_name}: {e}")
        sys.exit(1)


def format_date_string(time_val: int, wday: int, mon: int, mday: int, year: int, hour: int, minute: int, sec: int) -> str:
    month_str = f"{mon:02d}"
    day_str = f"{mday:02d}"
    hour_str = f"{hour:02d}"
    min_str = f"{minute:02d}"
    sec_str = f"{sec:02d}"
    if iso8601:
        return "0000-00-00T00:00:00Z" if time_val == 0 else f"{year}-{month_str}-{day_str}T{hour_str}:{min_str}:{sec_str}Z"
    else:
        if time_val == 0:
            return "Xxx Xxx 00 0000 00:00:00"
        return (f"{digit_to_day[str(wday)]} {month_str} {day_str} {year} {hour_str}:{min_str}:{sec_str}"
                if month_num else
                f"{digit_to_day[str(wday)]} {digit_to_month[month_str]} {day_str} {year} {hour_str}:{min_str}:{sec_str}")


def write_index_record(prev_day: str, prev_hour: str, prev_time: int, prev_cnt: int, delim: str) -> None:
    prev_vals = prev_day.split()
    if month_num:
        date_str = f"{digit_to_day[prev_vals[1]]} {prev_vals[2]} {prev_vals[0]} {prev_vals[3]}"
    else:
        date_str = f"{digit_to_day[prev_vals[1]]} {digit_to_month[prev_vals[2]]} {prev_vals[0]} {prev_vals[3]}"
    if INDEX_TYPE == INDEX_HOUR:
        date_str += f" {int(prev_hour):02d}:00:00"
    if prev_time > 0:
        with open(INDEX, "a", encoding=encoding_format) as index_file:
            index_file.write(f"{date_str}{delim} {prev_cnt}\n")


def main() -> None:
    global BODY, GROUP, PASSWD, TIME, INDEX, INDEX_TYPE, COMMA
    global iso8601, month_num, header, in_seconds, out_seconds

    parser = argparse.ArgumentParser(add_help=False, usage=argparse.SUPPRESS)
    parser.add_argument("-b", type=str, help="Specifies the body file location, else STDIN is used")
    parser.add_argument("-d", action="store_true", help="Output in comma delimited format")
    parser.add_argument("-g", type=str, help="Specifies the group file location, else GIDs are used")
    parser.add_argument("-p", type=str, help="Specifies the password file location, else UIDs are used")
    parser.add_argument("-h", action="store_true", help="Display a header with session information")
    parser.add_argument("-i", nargs=2, help="Specifies the index file with a summary of results")
    parser.add_argument("-V", action="store_true", help="Prints the version to STDOUT")
    parser.add_argument("-m", action="store_true", help="Dates have month as number instead of word")
    parser.add_argument("-y", action="store_true", help="Dates are displayed in ISO 8601 format")
    parser.add_argument("-z", type=str, help="Specify the timezone the data came from (in the local system format)")
    parser.add_argument("date", nargs="?", help="starting date (yyyy-mm-dd) or range (yyyy-mm-dd..yyyy-mm-dd)")
    args, unknown = parser.parse_known_args()

    for arg in unknown:
        if arg.startswith('-'):
            print(f"Unknown option: {arg}")
            usage()

    if args.b is not None:
        BODY = args.b
    if args.d:
        COMMA = 1
    if args.g is not None:
        GROUP = args.g
        load_group_info(GROUP)
    if args.p is not None:
        PASSWD = args.p
        load_passwd_info(PASSWD)
    if args.h:
        header = True
    if args.i is not None:
        if args.i[0] == "day":
            INDEX_TYPE = INDEX_DAY
        elif args.i[0] == "hour":
            INDEX_TYPE = INDEX_HOUR
        else:
            print("-i requires type 'day' or 'hour'")
            usage()
        INDEX = args.i[1]
        try:
            with open(INDEX, "w", encoding=encoding_format) as f:
                pass
        except Exception as e:
            print(f"Cannot open {INDEX}: {e}")
            sys.exit(1)
    if args.V:
        print_version()
        sys.exit(0)
    if args.m:
        month_num = True
    if args.y:
        iso8601 = True
    if args.z is not None:
        tz = args.z
        if tz.lower() == "list":
            tz_list = get_timezone_list()
            if tz_list:
                print("\n-----------------------------------")
                print("        TIMEZONE LIST")
                print("-----------------------------------")
                for tz_name in tz_list:
                    print(tz_name)
            else:
                print("pytz module not loaded -- cannot list timezones")
            sys.exit(0)
        try:
            if pytz is not None and tz in pytz.all_timezones:
                os.environ['TZ'] = tz
            else:
                print("Invalid timezone provided. Use '-z list' to list valid timezones.")
                usage()
        except Exception:
            os.environ['TZ'] = tz
    if args.date is not None:
        TIME = args.date
        if ".." in TIME:
            t_in, t_out = TIME.split("..")
        else:
            t_in = TIME
            t_out = ""
        in_seconds = parse_isodate(t_in)
        if in_seconds < 0:
            print(f"Invalid Date: {t_in}")
            sys.exit(1)
        if t_out:
            out_seconds = parse_isodate(t_out)
            if out_seconds < 0:
                print(f"Invalid Date: {t_out}")
                sys.exit(1)
        else:
            out_seconds = 0
    else:
        in_seconds = 0
        out_seconds = 0

    print_header()

    if INDEX:
        with open(INDEX, "w", encoding=encoding_format) as index_file:
            time_str = "Daily" if INDEX_TYPE == INDEX_DAY else "Hourly"
            if BODY:
                index_file.write(f"{time_str} Summary for Timeline of {BODY}\n\n")
            else:
                index_file.write(f"{time_str} Summary for Timeline of STDIN\n\n")

    read_body()
    print_tl()


if __name__ == "__main__":
    main()
