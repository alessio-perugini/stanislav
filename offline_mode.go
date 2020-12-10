package stanislav

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

var (
	AnalysisCsvFlow            = make(map[string][][]string)
	PeriodicCsvFLows           = make(map[string][][]string)
	ChronologicalOrderCsvFlows = make(map[string][][]string) //they key is actually the epoch
)

func OfflineMode() {
	opts = GetOptions()
	logger = opts.Logger
	dirs := WalkAllDirs(FlowPath) //gather all nprobe output files
	ReadFlowFiles(dirs, InspectFlow)
}

func ReadFlowFiles(dirs []string, inspect func(v RawFlow) bool) {
	for _, fPath := range dirs {
		file, err := os.OpenFile(fPath, os.O_RDONLY, 0777)
		if err != nil {
			log.Println(err)
			continue
		}

		r := csv.NewReader(file)
		r.Comma = '|'

		for {
			csvField, err := r.Read()
			if err != nil {
				break
			}
			//Parse csv fields
			Ipv4SrcAddr := csvField[0]
			Ipv4DstAddr := csvField[1]
			FirstSwitched, err := ConvStringToDate(csvField[7])
			if err != nil {
				continue
			}
			PortDst, err := strconv.Atoi(csvField[10])
			if err != nil {
				continue
			}
			InPkts, _ := strconv.Atoi(csvField[5])
			InBytes, _ := strconv.Atoi(csvField[6])
			LastSwitched, err := ConvStringToDate(csvField[8])
			if err != nil {
				continue
			}
			PortSrc, err := strconv.Atoi(csvField[9])
			if err != nil {
				continue
			}

			biflow, err := strconv.Atoi(csvField[20])
			if err != nil {
				continue
			}

			end := 6
			switch csvField[18] {
			case "reserved":
				end = 0
			case "idle_timeout":
				end = 1
			case "active_timeout":
				end = 2
			case "end_of_flow_detected":
				end = 3
			case "forced_end":
				end = 4
			case "lack_of_resources":
				end = 5
			case "unassigned":
				end = 6
			default:
				continue
			}

			riskName := csvField[21]
			riskRaw, err := strconv.Atoi(csvField[22])
			if err != nil {
				continue
			}

			rawFlow := RawFlow{
				Ipv4SrcAddr:     Ipv4SrcAddr,
				Ipv4DstAddr:     Ipv4DstAddr,
				FirstSwitched:   FirstSwitched,
				PortDst:         uint16(PortDst),
				PortSrc:         uint16(PortSrc),
				InPkts:          uint32(InPkts),
				InBytes:         uint32(InBytes),
				LastSwitched:    LastSwitched,
				EndReason:       uint8(end),
				BiFlowDirection: uint(biflow),
			}

			key := fmt.Sprintf("%s/%s/%d", rawFlow.Ipv4SrcAddr, rawFlow.Ipv4DstAddr, rawFlow.PortDst)
			isPeriodic := inspect(rawFlow)

			if val, ok := AnalysisCsvFlow[key]; ok {
				val = append(val, csvField)
				AnalysisCsvFlow[key] = val
			} else {
				AnalysisCsvFlow[key] = [][]string{csvField}
			}

			if isPeriodic {
				if val, ok := AnalysisCsvFlow[key]; ok {
					if pFlows, pfOk := PeriodicCsvFLows[key]; pfOk {
						lastPeriodic := strings.Join(pFlows[len(pFlows)-1], "|")
						elm := [][]string{val[len(val)-2], val[len(val)-1]}

						if strings.Compare(strings.Join(elm[0], "|"), lastPeriodic) == 0 {
							//put only last elm
							pFlows = append(pFlows, elm[1])
							PeriodicCsvFLows[key] = pFlows
							addChronologicalFlow(elm[1])
						} else { // put last 2 elem
							pFlows = append(pFlows, elm...)
							PeriodicCsvFLows[key] = pFlows
							addChronologicalFlow(elm...)
						}
					} else { //case that i've seen first periodic flow
						elm := [][]string{val[len(val)-3], val[len(val)-2], val[len(val)-1]}
						PeriodicCsvFLows[key] = elm
						addChronologicalFlow(elm...)
					}
				}
			}

			if !(Ipv4DstAddr != "" && Ipv4SrcAddr != "0.0.0.0" && Ipv4DstAddr != "0.0.0.0" &&
				!ExcludeMultiAndBroadcast(Ipv4SrcAddr) && !ExcludeMultiAndBroadcast(Ipv4DstAddr)) {
				continue
			}
			risk := riskRaw
			if risk > 0 && risk != 9 && risk != 8 && risk != 7 && risk != 128 && risk != 384 && risk != 640 && riskName != "" {
				AddPossibleThreat(Ipv4SrcAddr+"/"+Ipv4DstAddr, riskName)
			}
		}
		file.Close()
	}
}

func addChronologicalFlow(v ...[]string) {
	for _, record := range v {
		firstSwitched := record[7]
		if flow, ok := ChronologicalOrderCsvFlows[firstSwitched]; ok {
			flow = append(flow, record)
			ChronologicalOrderCsvFlows[firstSwitched] = flow
		} else {
			ChronologicalOrderCsvFlows[firstSwitched] = [][]string{record}
		}
	}
}
