# serverattackdetector
This file sifts through a csv file of server log information in the format of:
'date and time, duration, protocol, source IP address, source point, destination IP address, destination point, number of packets transferred, bytes transferred, flows, flags, Tos, class, attack type, attack ID, attack description' as shown in Test.csv. 

serverattackdetector.py builds an object based on the file given and when calling the method detect() will identify the first occurence of a suspicious log and repeated calls of detect() will find the next occurrence of a suspicous log.

A log is considered supicious if it satifies all the following properties:
1)It uses the UDP protocol.
2)It is marked “suspicious”.
3)It has a duration less than a millisecond
4)The previous communication using UDP (and marked “suspicious”) happened within one second before this one.

