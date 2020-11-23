package stanislav

import (
	"encoding/csv"
	"log"
	"os"
	"strconv"
)

func OfflineMode() {
	opts = GetOptions()
	logger = opts.Logger
	dirs := WalkAllDirs(FlowPath) //gather all nprobe output files
	ReadFlowFiles(dirs, InspectFlow)
}

func ReadFlowFiles(dirs []string, inspect func(v RawFlow)) {
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
			case "reserved": end = 0
			case "idle_timeout": end = 1
			case "active_timeout": end = 2
			case "end_of_flow_detected": end = 3
			case "forced_end": end = 4
			case "lack_of_resources": end = 5
			case "unassigned": end = 6
			default: continue
			}


			riskName :=csvField[21]
			riskRaw, err := strconv.Atoi(csvField[22])
			if err != nil{
				continue
			}

			rawFlow := RawFlow{
				Ipv4SrcAddr:   Ipv4SrcAddr,
				Ipv4DstAddr:   Ipv4DstAddr,
				FirstSwitched: FirstSwitched,
				PortDst:       uint16(PortDst),
				PortSrc:       uint16(PortSrc),
				InPkts:        uint32(InPkts),
				InBytes:       uint32(InBytes),
				LastSwitched:  LastSwitched,
				EndReason:     uint8(end),
				BiFlowDirection: uint(biflow),
			}

			InspectFlow(rawFlow)

			if !(Ipv4DstAddr != "" && Ipv4SrcAddr != "0.0.0.0" && Ipv4DstAddr != "0.0.0.0" &&
				!ExcludeMultiAndBroadcast(Ipv4SrcAddr) && !ExcludeMultiAndBroadcast(Ipv4DstAddr)) {
				continue
			}
			risk := (riskRaw)
			if risk > 0 && risk != 9 && risk != 8 && risk != 7 && risk != 128 && risk != 384 && risk!=640 &&riskName != "" {
				AddPossibleThreat(Ipv4SrcAddr + "/" + Ipv4DstAddr, riskName)
			}
		}
		file.Close()
	}
}
