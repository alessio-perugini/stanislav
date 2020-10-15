## Compile

```
$ go build ./main.go
```

## Note
The netflow exporter needs to set FLOW_END_REASON (id:136) and BIFLOW_DIRECTION (id:239) in order to handle long flow properly.

### nProbe example

Set your interface and ip:port, requires sudo to start.

```
nprobe -i [enp2s0] -n 127.0.0.1:2055 -b 2 -V 9 -T "%IPV4_SRC_ADDR %IPV4_DST_ADDR %IPV4_NEXT_HOP %INPUT_SNMP %OUTPUT_SNMP %IN_PKTS %IN_BYTES %FIRST_SWITCHED %LAST_SWITCHED %L4_SRC_PORT %L4_DST_PORT %TCP_FLAGS %PROTOCOL %SRC_TOS %SRC_AS %DST_AS %IPV4_SRC_MASK %IPV4_DST_MASK %FLOW_END_REASON %DIRECTION %BIFLOW_DIRECTION"
```

## Binaries

You can find `stanislav` binaries on the release tag

## How to use

``` 
./stanislav -tolerance 20 -nCompare 1 -ip "" -port 2055 -network eno1 -export "./peng_result.csv" -ja3 "./resources/ja3/ja3_fingerprints.csv" -geoip "./resources/GeoLite2-City.mmdb" -c2 "./resources/c2/c2Server.csv" -verbose 1
```

##### List all command

 ```
Usage: flow-periodicity [options]
  -bin uint
        number of bin in your bitmap (default 16)
  -bucket string
        bucket string for telegraf
  -c2 string
        file path of malicious ip
  -export string
        file path to save the peng result as csv
  -flowPath string
        dir path to load flows of nProbe
  -geoip string
        file path of geoip db
  -influxPort uint
        influxPort number (default 9999)
  -influxUrl string
        influx url (default "http://localhost")
  -interfaces
        show the list of all your network interfaces
  -ip string
        ip of netflow collector
  -ja3 string
        file path of malicious ja3 fingerprints
  -nCompare int
        number o time windows to compare to evaluate a possible periodicity (default 1)
  -network string
        name of your network interface
  -org string
        organization string for telegraf
  -pcap string
        pcap file to read
  -port string
        port of netflow collector (default "2055")
  -size uint
        size of your bitmap (default 1024)
  -timeFrame string
        interval time to detect port scans. Number + (s = seconds, m = minutes, h = hours) (default "15s")
  -token string
        auth token for influxdb
  -tolerance float
        maximum % tolerance before flag possible periodic flow. (default 20)
  -verbose uint
        verbosity level. (1=low,2=medium,3=high)
  -version
        output version

```