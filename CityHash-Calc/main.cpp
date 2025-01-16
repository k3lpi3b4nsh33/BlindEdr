#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <Windows.h>

#define FIRST_HASH 0xcbf29ce484222325
#define SECOND_HASH 0x100000001b3
#define THIRD_HASH  0xff51afd7ed558ccd
#define HASH_OFFSET 33

#define FUNCTION_SUFFIX "_CH"

#define CHASH(STR)    ( simple_cityhash( (LPCSTR)STR ) )

UINT32 simple_cityhash(LPCSTR cString) {
	int length = strlen(cString);
	uint64_t hash = FIRST_HASH;

	for (size_t i = 0; i < length; ++i) {
		hash ^= (uint64_t)cString[i];
		hash *= SECOND_HASH;
	}

	hash ^= hash >> HASH_OFFSET;
	hash *= THIRD_HASH;
	hash ^= hash >> HASH_OFFSET;

	return hash;
}


// Windows Defender
static CONST CHAR* WindowsDefender[] = {
	"WdFilter.sys","MpKslDrv.sys","mpsdrv.sys","WdNisDrv.sys","win32k.sys",
	NULL
};

// KES
static CONST CHAR* KES[] = {
	"klboot.sys", "klfdefsf.sys", "klrsps.sys", "klsnsr.sys", "klifks.sys", "klifaa.sys", "Klifsm.sys", "klam.sys", "klbg.sys",
	"kldback.sys", "kldlinf.sys", "kldtool.sys", "klif.sys", "Klcdp.sys", "Klshadow.sys", "Klsysrec.sys", "klvfs.sys", "Klfle.sys",
	"kldlhidp.sys", "kldlimpc.sys", "kldlksec.sys", "kldlksl.sys", "kldlndis.sys", "kldlnio.sys", "cm_km.sys", "kl1.sys", "kneps.sys",
	"klif_sha1.sys", "klbackupflt_sha1.sys", "cm_km_sha1.sys", "klbackupdisk.sys", "klbackupdisk_sha1.sys",
	"klmouflt.sys", "klmouflt_sha1.sys", "klpd.sys", "klpd_sha1.sys", "kldisk.sys", "kldisk_sha1.sys", "klelam.sys", "klflt.sys", "klflt_sha1.sys",
	"Klvirt.sys", "Klbackupflt.sys", "Klsec.sys", "klvfs.sys", "klbackupflt.sys", "klim6.sys", "kldl.sys", "kldlfmgr.sys", "kldlfwpk.sys",
	"kneps_sha1.sys", "klpnpflt.sys", "klpnpflt_sha1.sys", "klwtp.sys", "klwtp_sha1.sys", "klim6_sha1.sys", "klkbdflt.sys", "klkbdflt_sha1.sys",

	NULL
};



static CONST CHAR* Huorong[] = {
	"sysdiag_win10.sys","sysdiag.sys",
};

// TrendMicro
static CONST CHAR* TrendMicro[] = {
	"TmPreFilter.sys","TmXPFlt.sys",
	
	NULL
};

// I hate 360 4ever.
static CONST CHAR* Fucking360[] = {
	"360AvFlt.sys",
	"360qpesv64.sys","360AntiSteal64.sys","360AntiSteal.sys","360qpesv.sys","360FsFlt.sys","360Box64.sys","360netmon.sys","360AntiHacker64.sys","360Hvm64.sys","360qpesv64.sys","360AntiHijack64.sys","360AntiExploit64.sys","DsArk64.sys","360Sensor64.sys","DsArk.sys",

	NULL
};


static CONST CHAR* QQ[] = {
	"QMUdisk64_ev.sys","QQSysMonX64_EV.sys","TAOKernelEx64_ev.sys","TFsFltX64_ev.sys","TAOAcceleratorEx64_ev.sys","QQSysMonX64.sys","TFsFlt.sys",

	NULL
};


static CONST CHAR* QAX[] = {
	"QaxNfDrv.sys","QKBaseChain64.sys","QKNetFilter.sys","QKSecureIO.sys","QesEngEx.sys","QkHelp64.sys","qmnetmonw64.sys",

	NULL
};

typedef struct {
    const char** array;
    const char* name;
} ArrayInfo;


const char* GOBAL_FUNCTION[] = {
	"OpenProcessToken",
	"LookupPrivilegeValueA",
	"AdjustTokenPrivileges",
	"FltEnumerateFilters",
	"NtDuplicateObject",
	"NtOpenThreadTokenEx",
	"CmUnRegisterCallback",
	"PsSetCreateProcessNotifyRoutine",
	"PsSetCreateThreadNotifyRoutine",
	"PsSetLoadImageNotifyRoutine",
	NULL
};


const char* GOBAL_MODULE[] = {
	"kernel32.dll",
	"ntdll.dll",
	"FLTMGR.SYS",
	"ntoskrnl.exe",
	"advapi32.dll",
	NULL
};

void format_module_name(const char* input, char* output) {
	size_t j = 0;
	for (size_t i = 0; input[i] != '\0'; ++i) {
		if (input[i] != '.') {
			output[j++] = input[i];
		}
	}
	output[j] = '\0';
}


void print_hash_definitions(const char* suffix, const char* array[], int format_name) {
	char formatted_name[256]; 
	char temp_name[256];      
	for (size_t i = 0; array[i] != NULL; ++i) {
		
		if (format_name) {
			format_module_name(array[i], temp_name); 
		}
		else {
			strncpy_s(temp_name, sizeof(temp_name), array[i], _TRUNCATE); 
		}

		
		sprintf_s(formatted_name, sizeof(formatted_name), "%s%s", temp_name, suffix);

		
		printf("#define %-40s 0x%0.8X\n", formatted_name, CHASH(array[i]));
	}
	printf("\n");
}

int main() {
    const ArrayInfo arrays[] = {
        {WindowsDefender, "WindowsDefender"},
        {KES, "KES"},
        {Huorong, "Huorong"},
        {TrendMicro, "TrendMicro"},
        {Fucking360, "Fucking360"},
        {QQ, "QQ"},
        {QAX, "QAX"},
        {NULL, NULL}
    };

    for (const ArrayInfo* info = arrays; info->array != NULL; info++) {
        printf("// %s\n", info->name);
        int count = 0;
        for (const char** ptr = info->array; *ptr != NULL; ptr++) {
            printf("0x%08X,", CHASH(*ptr));
            if (++count % 12 == 0) {
                printf("\n");
            }
        }
        printf("\n\n");
    }


	// print hash
	print_hash_definitions(FUNCTION_SUFFIX, GOBAL_FUNCTION, 0);

	// print hash
	print_hash_definitions(FUNCTION_SUFFIX, GOBAL_MODULE, 1);

    return 0;
}