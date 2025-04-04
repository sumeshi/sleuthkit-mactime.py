perl src/mactime.pl -b ./sample/bodyfile.txt -d -y -z GMT > perl-result.txt
python src/mactime.py -b ./sample/bodyfile.txt -d -y -z GMT > python-result.txt

diff perl-result.txt python-result.txt