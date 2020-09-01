# capx
A Python and tshark script for command line analysis of network traffic.

Requires tshark:
```
sudo apt install tshark
```
And also some python packages:
```
pip2 install -r requirements.txt
```

If you have some cap files in this directory, try:
```
./capx.py *.cap *.pcap *.pcapng
```

And also:
```
./capx.py sum *.cap *.pcap *.pcapng
```
This will give you a summery of the files, grouping similar packets together in one line.

Finaly try:
```
./capx.py --help
```
