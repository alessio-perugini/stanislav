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

You can find `flow-periodicity` binaries on the release tag

## How to use

``` 
./flow-periodicity -tolerance 5 -nCompare 3 -ip "" -port 2055
```

##### List all command

 ```
Usage: flow-periodicity [options]
  -flowPath string
        dir path to load flows of nProbe
  -ip string
        ip of netflow collector
  -nCompare int
        number o time windows to compare to evaluate a possible periodicity (default 3)
  -port string
        port of netflow collector (default "2055")
  -tolerance float
        maximum % tolerance before flag possible periodic flow. (default 5%)
```