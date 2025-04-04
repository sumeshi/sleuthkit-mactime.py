# mactime.py
A Python reimplementation of mactime.pl from The Sleuth Kit®.

## Usage
```
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
```

### Example
```bash
$ python mactime.py -b ./sample/bodyfile.txt -d -y -z GMT
```

## Installation
### Executable(Windows)
```
> mactime.exe
```

### Python Environment
```
$ pip install pytz
$ python mactime.py
```

# License
This program is licensed under the same terms as The Sleuth Kit, specifically the Common Public License 1.0 (CPL 1.0). For additional details, please refer to the original license statements included with The Sleuth Kit.
