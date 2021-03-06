package stanislav

import (
	"encoding/json"
	"fmt"
	"math"
	"time"
)

func UnmarshalPeriodicFlows(data []byte) (PeriodicFlows, error) {
	var f PeriodicFlows
	err := json.Unmarshal(data, &f)
	return f, err
}

func (f *PeriodicFlows) Marshal() ([]byte, error) {
	return json.Marshal(f)
}

type PeriodicFlows map[string]*FlowInfo
type AllFlows map[string]*FlowInfo

type FlowInfo struct {
	TWDuration           float64       `json:"frequency"`
	ServerPort           uint16        `json:"server_port"`
	Client               string        `json:"client"`
	PeriodicityCounter   int           `json:"num_periodic_loops_accounted"`
	Server               string        `json:"server"`
	TimeWindowsExpiresAt time.Time     `json:"-"`
	LastSwitched         time.Time     `json:"-"`
	CurrentlyPeriodic    bool          `json:"-"`
	Deviation            time.Duration `json:"-"`
}

type RawFlow struct {
	Ipv4SrcAddr     string
	Ipv4DstAddr     string
	FirstSwitched   time.Time
	PortDst         uint16
	PortSrc         uint16
	InPkts          uint32
	InBytes         uint32
	LastSwitched    time.Time
	EndReason       uint8
	Direction       uint
	BiFlowDirection uint
}

func SetTwDuration(fi *FlowInfo, rf RawFlow) {
	fi.TWDuration = math.Round(rf.FirstSwitched.Sub(fi.LastSwitched).Seconds()) //TODO autoregolare e non dropparla troppo
	if fi.TWDuration <= 3.0 {
		fi.TWDuration = 3.0 //sec
	}
	fi.Deviation = ConvFloatToDuration((fi.TWDuration * PercentageDeviation) / 100.0)
	fi.TimeWindowsExpiresAt = rf.FirstSwitched.Add(ConvFloatToDuration(fi.TWDuration))
	fi.LastSwitched = rf.LastSwitched
}

//TODO remove bool return, used for analysis only
func InspectFlow(rf RawFlow) bool {
	if !(rf.Ipv4DstAddr != "" && rf.Ipv4SrcAddr != "0.0.0.0" && rf.Ipv4DstAddr != "0.0.0.0" &&
		!ExcludeMultiAndBroadcast(rf.Ipv4SrcAddr) && !ExcludeMultiAndBroadcast(rf.Ipv4DstAddr)) {
		return false
	}
	//TODO create a function that handles C2 server blocklist

	if name, ok := blackListIp[rf.Ipv4DstAddr]; ok {
		AddPossibleThreat(rf.Ipv4DstAddr, "c2 server "+name)
		logger.Printf("[%s] appears in the blocked c2 list as %s!\n", rf.Ipv4DstAddr, name)
	}
	if name, ok := blackListIp[rf.Ipv4SrcAddr]; ok {
		AddPossibleThreat(rf.Ipv4SrcAddr, "c2 server "+name)
		logger.Printf("[%s] appears in the blocked c2 list as %s!\n", rf.Ipv4SrcAddr, name)
	}

	//https://tools.ietf.org/html/rfc5102#section-5
	if rf.EndReason == 2 { //TODO check and remove if in the map
		return false
	}
	//https://tools.ietf.org/html/rfc5103
	if rf.BiFlowDirection == 2 { //TODO check and remove if in the map
		return false
	}

	key := fmt.Sprintf("%s/%s/%d", rf.Ipv4SrcAddr, rf.Ipv4DstAddr, rf.PortDst)

	if flowInfo, flowSeen := analisi[key]; flowSeen {
		if flowInfo.TimeWindowsExpiresAt.IsZero() { //compute new TimeWindow
			SetTwDuration(flowInfo, rf)
		} else {
			maxTime := flowInfo.TimeWindowsExpiresAt.Add(flowInfo.Deviation)
			minTime := flowInfo.TimeWindowsExpiresAt.Add(-flowInfo.Deviation)

			if flowInfo.TimeWindowsExpiresAt.After(rf.FirstSwitched) {
				flowInfo.LastSwitched = rf.LastSwitched
			} else { //TW expired
				if minTime.Before(rf.FirstSwitched) && maxTime.After(rf.FirstSwitched) {
					SetTwDuration(flowInfo, rf) //TODO spostare in fondo all'if e mettere dentro il controllo dell'endreason
					flowInfo.PeriodicityCounter++
					flowInfo.LastSwitched = rf.LastSwitched
					if flowInfo.PeriodicityCounter >= SeenXtime {
						PeriodiFlows[key] = flowInfo
						ChangePeriodicStatus(key, flowInfo, true)
						return true
					}
				} else {
					if flowInfo.PeriodicityCounter >= SeenXtime {
						ChangePeriodicStatus(key, flowInfo, false)
						ResetCurrentTW(key, flowInfo, rf.LastSwitched)
					}
				}
			}
		}
	} else { //If the new key isn't in the map prepare and add new FlowInfo
		analisi[key] = &FlowInfo{
			Client:       rf.Ipv4SrcAddr,
			Server:       rf.Ipv4DstAddr,
			ServerPort:   rf.PortDst,
			LastSwitched: rf.LastSwitched,
		}
	}

	return false
}

func ResetCurrentTW(key string, fi *FlowInfo, lastSwitched time.Time) {
	fi.LastSwitched = lastSwitched
	fi.TimeWindowsExpiresAt = time.Time{} //Resetting TW
	analisi[key] = fi
}

func ChangePeriodicStatus(key string, fi *FlowInfo, v bool) {
	if v && fi.CurrentlyPeriodic || !v && !fi.CurrentlyPeriodic {
		return
	}

	if v && !fi.CurrentlyPeriodic { //TODO re-enable for live mode!
		//AddPossibleThreat(key, fmt.Sprintf("periodic frequency: %.2fs seen %d times.", fi.TWDuration, fi.PeriodicityCounter))
		if Conf.Verbose > 0 {
			logger.Printf("%s \tbecame periodic! Seen %d times. Frequency: %.2fs ", key, fi.PeriodicityCounter, fi.TWDuration)
		}
	} else {
		if Conf.Verbose > 0 {
			logger.Printf("%s \tnot periodic anymore! Seen %d times. Frequency: %.2fs ", key, fi.PeriodicityCounter, fi.TWDuration)
		}
	}

	fi.CurrentlyPeriodic = v
}

func ExcludeMultiAndBroadcast(ip string) bool {
	return IsMulticastAddress(ip) || IsBroadcastAddress(ip)
}
