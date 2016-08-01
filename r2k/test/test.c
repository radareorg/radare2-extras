// SkUaTeR 2016 - This file is only for test dont use !!!
#include "windows.h"
#include "stdio.h"
#define strDeviceName L"\\\\.\\r2k\\"
typedef struct _PPA {
	LARGE_INTEGER address;
	DWORD len;
	unsigned char buffer;
} PA, * PPA;

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

#define INTEGER INT
#define CLOSE_DRIVER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_READ_PHYS_MEM CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_READ_KERNEL_MEM CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_GET_PHYSADDR CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_WRITE_PHYS_MEM CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_GET_SYSTEM_MODULES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80a, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_WRITE_KERNEL_MEM CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

BOOL IsDriverPresent (VOID) {
	HANDLE hFile;
	hFile = CreateFile (strDeviceName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_DIRECTORY, 0);
	if (hFile != INVALID_HANDLE_VALUE) {
		CloseHandle (hFile);
		return TRUE;
	}
	return FALSE;
}

void GetDriverInfo (VOID) {
	LPVOID lpBuffer = NULL;
	LPVOID lpBufferReal = NULL;
	LPVOID lpBufMods = NULL;
	LPVOID lpBufWrite = NULL;
	HANDLE hDevice = INVALID_HANDLE_VALUE;
	DWORD Status = 1;
	ULONG bRead;
	PPA t,PPAWrite;
	PA direccion;
	CHAR * buffer;
	int i;
	do {
#define BUFMODSIZE 1024*1024
#define BUFSIZE 1024
#define BUFREADSIZE 1024
		if (!(lpBufMods = malloc (BUFMODSIZE))) {
			break;
		}
		hDevice = CreateFile (strDeviceName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0);
		if (hDevice == INVALID_HANDLE_VALUE) {
			break;
		}
		if (!(DeviceIoControl (hDevice, IOCTL_GET_SYSTEM_MODULES, lpBufMods, BUFMODSIZE, lpBufMods, BUFMODSIZE, &bRead, NULL))) {
			break;
		}
		PRTL_PROCESS_MODULES pm = (PRTL_PROCESS_MODULES)lpBufMods;
		PRTL_PROCESS_MODULE_INFORMATION pMod = pm->Modules;
		if (!(lpBuffer = malloc (BUFSIZE))) {
			break;
		}
		if (!(lpBufWrite = malloc (BUFSIZE))) {
			break;
		}
		lpBufferReal = VirtualAlloc (NULL, 1, MEM_COMMIT, PAGE_READWRITE);
		if (!(lpBufferReal = malloc (BUFREADSIZE))) {
			break;
		}
		for (i = 0; i < pm->NumberOfModules; i++) {
			printf("%p = %-50s ", pMod[i].ImageBase, pMod[i].FullPathName);
			t = (PPA)lpBuffer;
			t->address.QuadPart = pMod[i].ImageBase;
			t->len = 256;
			if (!(DeviceIoControl (hDevice, IOCTL_READ_KERNEL_MEM, lpBuffer, BUFSIZE, lpBuffer, BUFSIZE, &bRead, NULL))) {
				printf (" [FAIL]\n");
			} else {
				printf (" [READED]");
				PPAWrite = (PPA)lpBufWrite;
				PPAWrite->address.QuadPart = pMod[i].ImageBase;
				PPAWrite->len = 256;
				memcpy (&PPAWrite->buffer, lpBuffer, 256);
				if (!(DeviceIoControl (hDevice, IOCTL_WRITE_KERNEL_MEM, lpBufWrite, BUFSIZE, lpBufWrite, BUFSIZE, &bRead, NULL))) {
					printf (" [FAIL]");
				}
				else {
					printf (" [WRITTEN]");
				}
			}
			if ((DeviceIoControl (hDevice, IOCTL_GET_PHYSADDR, &pMod[i].ImageBase, sizeof(ULONGLONG), lpBufferReal, BUFREADSIZE, &bRead, NULL))) {
				t = (PPA)lpBufferReal;
				t->len = 256;
				if ((DeviceIoControl (hDevice, IOCTL_READ_PHYS_MEM, lpBufferReal, BUFREADSIZE, lpBufferReal, BUFREADSIZE, &bRead, NULL))) {
					if (!memcmp (lpBufferReal, lpBuffer, 256)) {
						printf (" *** Verified ***\n");
					}
				}
			}
		}
		//fffff800`02a62000
		//ff ff f8 00 `02 a1 d0 00
		direccion.address.QuadPart = 0x482d0000; // pMod[0].ImageBase;
		t = (PPA)lpBuffer;
		t->address.HighPart = direccion.address.HighPart;
		t->address.LowPart = direccion.address.LowPart;
		t->len = 256;
		if (!(DeviceIoControl (hDevice, IOCTL_READ_KERNEL_MEM, lpBuffer, BUFSIZE, lpBuffer, BUFSIZE, &bRead, NULL))) {
			break;
		}
		ULONGLONG addr = direccion.address.QuadPart;
		if (!(DeviceIoControl (hDevice, IOCTL_GET_PHYSADDR, &addr, sizeof(ULONGLONG), lpBuffer, BUFSIZE, &bRead, NULL))) {
			break;
		}
		t = (PPA)lpBuffer;
		//t->address.HighPart = 0;
		//t->address.LowPart = 0x02a1d013;
		t->len = 256;
		if (!(DeviceIoControl(hDevice, IOCTL_READ_PHYS_MEM, lpBuffer, BUFSIZE, lpBuffer, BUFSIZE, &bRead, NULL))) {
			break;
		}
		t = (PPA)lpBuffer;
		t->address.HighPart = 0;
		t->address.LowPart = 0x02a1d013;
		t->len = 5;
		strcpy(&t->buffer, "abcde");
		if (!(DeviceIoControl (hDevice, IOCTL_WRITE_PHYS_MEM, lpBuffer, BUFSIZE, lpBuffer, BUFSIZE, &bRead, NULL))) {
			break;
		}
		printf ("[ok] GetDriverInfo: Result = %s \n", lpBuffer);
		Status = NO_ERROR;
	} while (FALSE);
	if (Status != NO_ERROR) {
		Status = GetLastError ();
		printf ("[x] GetDriverInfo: Error %x\n", Status);
	}
	if (lpBuffer) {
		free (lpBuffer);
	}
	if (hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle (hDevice);
	}
}

int test() {
	printf ("Device name: %S\n", strDeviceName);
	if (IsDriverPresent () == TRUE) {
		printf ("[ok] IsDriverPresent: Driver locaited.\n");
		GetDriverInfo ();
	}
	else {
		printf ("[x] !!! Error cant locate driver.\n");
	}
}

int main() {
	test ();
	return 0;
}
