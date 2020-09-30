package periodicity

import (
	"encoding/json"
	"fmt"
	"log"
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
	TimeWindows          []TimeWindow  `json:"-"`
	LastSwitched         time.Time     `json:"-"`
	CurrentlyPeriodic    bool          `json:"-"`
	Deviation            time.Duration `json:"-"`
}

type TimeWindow struct {
	Duration        time.Duration
	LastFlowTime    time.Time
	TotalJitter     float64
	NumberSeenFlows int
	Jitter          float64
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

func InspectFlow(rf RawFlow) {
	if !(rf.Ipv4DstAddr != "" && rf.Ipv4SrcAddr != "0.0.0.0" && rf.Ipv4DstAddr != "0.0.0.0" &&
		!ExcludeMultiAndBroadcast(rf.Ipv4SrcAddr) && !ExcludeMultiAndBroadcast(rf.Ipv4DstAddr)) {
		return
	}

	//https://tools.ietf.org/html/rfc5102#section-5
	if rf.EndReason == 2 {
		return
	}
	//https://tools.ietf.org/html/rfc5103
	if rf.BiFlowDirection == 2 {
		return
	}

	var key string
	key = fmt.Sprintf("%s/%s/%d", rf.Ipv4SrcAddr, rf.Ipv4DstAddr, rf.PortDst)

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
					SetTwDuration(flowInfo, rf)
					flowInfo.PeriodicityCounter++
					flowInfo.LastSwitched = rf.LastSwitched
					if flowInfo.PeriodicityCounter >= NTwToCompare {
						PeriodiFlows[key] = flowInfo
						ChangePeriodicStatus(key, flowInfo, true)
					}
				} else {
					if flowInfo.PeriodicityCounter >= NTwToCompare {
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
}

func InspectFlowUsingJitter(rf RawFlow) {
	if !(rf.Ipv4DstAddr != "" && rf.Ipv4SrcAddr != "0.0.0.0" && rf.Ipv4DstAddr != "0.0.0.0" &&
		!ExcludeMultiAndBroadcast(rf.Ipv4SrcAddr) && !ExcludeMultiAndBroadcast(rf.Ipv4DstAddr)) {
		return
	}

	//https://tools.ietf.org/html/rfc5102#section-5
	if rf.EndReason == 2 {
		return
	}

	key := fmt.Sprintf("%s/%s/%d", rf.Ipv4SrcAddr, rf.Ipv4DstAddr, rf.PortDst)
	if flowInfo, flowSeen := analisi[key]; flowSeen {
		if flowInfo.TimeWindowsExpiresAt.IsZero() { //compute new TimeWindow
			SetTwDuration(flowInfo, rf)

			//add to list the current flow
			tw := TimeWindow{LastFlowTime: rf.FirstSwitched, NumberSeenFlows: 1, Duration: ConvFloatToDuration(flowInfo.TWDuration)}
			flowInfo.TimeWindows = append(flowInfo.TimeWindows, tw)
		} else {
			maxTime := flowInfo.TimeWindowsExpiresAt.Add(flowInfo.Deviation)
			minTime := flowInfo.TimeWindowsExpiresAt.Add(-flowInfo.Deviation)

			if flowInfo.TimeWindowsExpiresAt.After(rf.FirstSwitched) { // timewindow not exceed
				indexLastTW := len(flowInfo.TimeWindows) - 1
				flowInfo.LastSwitched = rf.LastSwitched
				lastTw := flowInfo.TimeWindows[indexLastTW]

				lastTw.TotalJitter += math.Abs(rf.FirstSwitched.Sub(lastTw.LastFlowTime).Seconds())
				lastTw.NumberSeenFlows++
				lastTw.LastFlowTime = rf.FirstSwitched

				flowInfo.TimeWindows[indexLastTW] = lastTw
			} else { //time window expired
				timeElapsedAfterLastInsert := rf.FirstSwitched.Sub(maxTime).Seconds()
				nTWSkipped := timeElapsedAfterLastInsert / flowInfo.TWDuration

				if nTWSkipped <= 1.0 { //Compute jitter for last TW
					indexLastTW := len(flowInfo.TimeWindows) - 1
					lastTw := flowInfo.TimeWindows[indexLastTW]
					lastTw.Jitter = ComputeJitter(lastTw)
					flowInfo.TimeWindows[indexLastTW] = lastTw //Update jitter TODO add pointer

					//Check if i can analyze last X TW. Used to mark possible periodicity
					if len(flowInfo.TimeWindows) == NTwToCompare {
						if IsPeriodic(*flowInfo, indexLastTW, NTwToCompare) {
							ChangePeriodicStatus(key, flowInfo, true)

							flowInfo.PeriodicityCounter += NTwToCompare
							flowInfo.TimeWindows = flowInfo.TimeWindows[:0] //clear last X TW

							if flowInfo.PeriodicityCounter > 2 {
								PeriodiFlows[key] = flowInfo //TODO mode in the if?
							}
						}
					}
				} else {
					ChangePeriodicStatus(key, flowInfo, false)
					ResetCurrentTW(key, flowInfo, rf.LastSwitched)
					return
				}

				if minTime.Before(rf.FirstSwitched) && maxTime.After(rf.FirstSwitched) {
					SetTwDuration(flowInfo, rf)

					flowInfo.LastSwitched = rf.LastSwitched
					tw := TimeWindow{LastFlowTime: rf.FirstSwitched, NumberSeenFlows: 1, Duration: ConvFloatToDuration(flowInfo.TWDuration)}
					flowInfo.TimeWindows = append(flowInfo.TimeWindows, tw)
				} else {
					ResetCurrentTW(key, flowInfo, rf.LastSwitched)
				}
			}
		}
	} else { //If the new key isn't in the map prepare and add new FlowInfo
		analisi[key] = &FlowInfo{
			Client:       rf.Ipv4SrcAddr,
			Server:       rf.Ipv4DstAddr,
			ServerPort:   rf.PortDst,
			LastSwitched: rf.LastSwitched,
			TimeWindows:  make([]TimeWindow, 0, NTwToCompare),
		}
	}
}

func InspectFlowOLD(rf RawFlow) {
	if !(rf.Ipv4DstAddr != "" && rf.Ipv4SrcAddr != "0.0.0.0" && rf.Ipv4DstAddr != "0.0.0.0" &&
		!ExcludeMultiAndBroadcast(rf.Ipv4SrcAddr) && !ExcludeMultiAndBroadcast(rf.Ipv4DstAddr)) {
		return
	}

	key := fmt.Sprintf("%s/%s/%d", rf.Ipv4SrcAddr, rf.Ipv4DstAddr, rf.PortDst)
	if flowInfo, flowSeen := analisi[key]; flowSeen {
		//https://tools.ietf.org/html/rfc5102#section-5
		if rf.EndReason == 2 { //if is 2 the flow is not end
			return
		}

		if flowInfo.TimeWindowsExpiresAt.IsZero() { //compute new TimeWindow
			SetTwDuration(flowInfo, rf)

			//add to list the current flow
			tw := TimeWindow{LastFlowTime: rf.FirstSwitched, NumberSeenFlows: 1, Duration: ConvFloatToDuration(flowInfo.TWDuration)}
			flowInfo.TimeWindows = append(flowInfo.TimeWindows, tw)
		} else {
			//maxTime := flowInfo.TimeWindowsExpiresAt.Add(flowInfo.Deviation)
			//minTime := flowInfo.TimeWindowsExpiresAt.Add(-flowInfo.Deviation)

			if flowInfo.TimeWindowsExpiresAt.After(rf.FirstSwitched) { // timewindow not exceed
				indexLastTW := len(flowInfo.TimeWindows) - 1
				flowInfo.LastSwitched = rf.LastSwitched
				lastTw := flowInfo.TimeWindows[indexLastTW]

				lastTw.TotalJitter += math.Abs(rf.FirstSwitched.Sub(lastTw.LastFlowTime).Seconds())
				lastTw.NumberSeenFlows++
				lastTw.LastFlowTime = rf.FirstSwitched

				flowInfo.TimeWindows[indexLastTW] = lastTw
			} else { //time window expired
				timeElapsedAfterLastInsert := rf.FirstSwitched.Sub(flowInfo.TimeWindowsExpiresAt).Seconds()
				nTWSkipped := timeElapsedAfterLastInsert / flowInfo.TWDuration

				if nTWSkipped < 1.2 { //Compute jitter for last TW
					indexLastTW := len(flowInfo.TimeWindows) - 1
					lastTw := flowInfo.TimeWindows[indexLastTW]
					lastTw.Jitter = ComputeJitter(lastTw)
					flowInfo.TimeWindows[indexLastTW] = lastTw //Update jitter TODO add pointer

					//Check if i can analyze last X TW. Used to mark possible periodicity
					if len(flowInfo.TimeWindows) == NTwToCompare {
						if IsPeriodic(*flowInfo, indexLastTW, NTwToCompare) {
							ChangePeriodicStatus(key, flowInfo, true)

							flowInfo.PeriodicityCounter += NTwToCompare
							flowInfo.TimeWindows = flowInfo.TimeWindows[:0] //clear last X TW
							PeriodiFlows[key] = flowInfo                    //TODO mode in the if?
						} else {
							ChangePeriodicStatus(key, flowInfo, false)
							ResetCurrentTW(key, flowInfo, rf.LastSwitched)
							return
						}
					}
				} else {
					ChangePeriodicStatus(key, flowInfo, false)
					ResetCurrentTW(key, flowInfo, rf.LastSwitched)
					return
				}

				//TODO refactor this
				SetTwDuration(flowInfo, rf)

				//add to list the current flow
				tw := TimeWindow{LastFlowTime: rf.FirstSwitched, NumberSeenFlows: 1, Duration: ConvFloatToDuration(flowInfo.TWDuration)}
				flowInfo.TimeWindows = append(flowInfo.TimeWindows, tw)
			}
		}
	} else { //If the new key isn't in the map prepare and add new FlowInfo
		analisi[key] = &FlowInfo{
			Client:       rf.Ipv4SrcAddr,
			Server:       rf.Ipv4DstAddr,
			ServerPort:   rf.PortDst,
			LastSwitched: rf.LastSwitched,
			TimeWindows:  make([]TimeWindow, 0, NTwToCompare),
		}
	}
}

func ResetCurrentTW(key string, fi *FlowInfo, lastSwitched time.Time) {
	fi.TimeWindows = fi.TimeWindows[:0] //clear last X TW
	fi.LastSwitched = lastSwitched
	fi.TimeWindowsExpiresAt = time.Time{} //Resetting TW
	analisi[key] = fi
}

func ChangePeriodicStatus(key string, fi *FlowInfo, v bool) {
	if v && fi.CurrentlyPeriodic || !v && !fi.CurrentlyPeriodic {
		return
	}

	if v && !fi.CurrentlyPeriodic {
		log.Printf("%s \tbecame periodic! Seen %d times. Frequency: %.2fs ", key, fi.PeriodicityCounter, fi.TWDuration)
	} else {
		log.Printf("%s \tnot periodic anymore! Seen %d times. Frequency: %.2fs ", key, fi.PeriodicityCounter, fi.TWDuration)
	}

	fi.CurrentlyPeriodic = v
}

func IsPeriodic(v FlowInfo, twOffset, nWindowToCompare int) bool {
	if len(v.TimeWindows) < 1 || twOffset-(nWindowToCompare-1) < 0 || twOffset < 0 || nWindowToCompare <= 0 {
		return false
	}
	maxAllowdJitter := v.TWDuration - ((v.TWDuration * PercentageDeviation) / 100.0)
	if len(v.TimeWindows) == 1 {
		if v.TimeWindows[0].NumberSeenFlows == 2 {
			fmt.Print()
		}
		return v.TimeWindows[0].Jitter < maxAllowdJitter
	}

	jitterTw := make([]float64, nWindowToCompare)
	for i := 0; i < nWindowToCompare; i++ {
		jitterTw[nWindowToCompare-i-1] = v.TimeWindows[twOffset-i].Jitter

		if jitterTw[nWindowToCompare-i-1] == -1 {
			return false
		}
	}

	jitterDiff, jitterTotal, jitterAvg := 0.0, 0.0, 0.0
	for i := nWindowToCompare - 1; i > 0; i-- {
		jitterDiff = math.Abs(jitterTw[i-1] - jitterTw[i])
		jitterTotal += jitterDiff
	}

	jitterAvg = jitterTotal / float64(nWindowToCompare-1)

	return jitterAvg < maxAllowdJitter
}

//jitter = sum(|x(i) - x(i-1)|) / (n-1))
func ComputeJitter(tw TimeWindow) float64 {
	if tw.NumberSeenFlows == 1 {
		return tw.TotalJitter
	}
	return tw.TotalJitter / float64(tw.NumberSeenFlows-1)
}

func ExcludeMultiAndBroadcast(ip string) bool {
	return IsMulticastAddress(ip) || IsBroadcastAddress(ip)
}
