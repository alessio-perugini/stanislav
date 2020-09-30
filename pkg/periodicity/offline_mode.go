package periodicity

import (
	"encoding/csv"
	"log"
	"os"
	"strconv"
)

func OfflineMode() {
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

			end, err := strconv.Atoi(csvField[17])
			if err != nil {
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
			}

			InspectFlow(rawFlow)

		}
		file.Close()
	}
}
