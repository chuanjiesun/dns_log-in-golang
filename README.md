# dns_log-in-golang
  capture DNS QUERY  traffic ,written in golang,mirror mode support.  
  This program use gopacket to capture DNS REQUEST,and use beego ORM MYSQL to log in mysql database.

# Requirement
  `golang` `gopacket` `beego` `go-sql-driver` `libpcap-dev`

# Test
Test on Debian 

# Usage
```go
go run dns_log.go
```
OR compile it to binary,and execute it.

You should edit database configurations to adapt to yours.   
`1. create a database`  
`2. the program will auto create table and log the dns query`

# There are screenshots
![](https://github.com/chuanjiesun/dns_log-in-golang/blob/master/g1.JPG)  
![](https://github.com/chuanjiesun/dns_log-in-golang/blob/master/g2.JPG)

