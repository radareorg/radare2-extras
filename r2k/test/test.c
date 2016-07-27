#include "windows.h"
#include "stdio.h"
#define strDeviceName     L"\\\\.\\r2k\\"
typedef  struct _PPA {
	LARGE_INTEGER address;
	DWORD len;
	unsigned char buffer;
} PA, * PPA;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;         // Not filled in
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

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

#define INTEGER INT
#define		CLOSE_DRIVER				CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define		IOCTL_READ_PHYS_MEM			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define		IOCTL_READ_KERNEL_MEM		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define		IOCTL_GET_PHYSADDR			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define		IOCTL_WRITE_PHYS_MEM		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define		IOCTL_GET_SYSTEM_MODULES	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80a, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define		IOCTL_WRITE_KERNEL_MEM		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)


BOOL IsDriverPresent(VOID)
{
	BOOL	Ret = FALSE;
	HANDLE	hFile;

	hFile = CreateFile(strDeviceName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_DIRECTORY, 0);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
		Ret = TRUE;
	}
	return(Ret);
}

void GetDriverInfo(VOID)
{
	LPVOID		lpBuffer = NULL;
	LPVOID		lpBufferReal = NULL;
	LPVOID		lpBufMods = NULL;
	LPVOID		lpBufWrite = NULL;

	HANDLE		hDevice = INVALID_HANDLE_VALUE;
	DWORD		Status = 1;
	ULONG		bRead;
	PPA         t,PPAWrite;
	PA			direccion;
	CHAR *      buffer;
	int i;
	do	// no es un loop , es para evitar gotos ;)
	{
		#define bufmodsize 1024*1024
		if (!(lpBufMods = malloc(bufmodsize)))
			break;
		
		hDevice = CreateFile(strDeviceName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0);
		if (hDevice == INVALID_HANDLE_VALUE)
			break;
		
		
		if (!(DeviceIoControl(hDevice, IOCTL_GET_SYSTEM_MODULES, lpBufMods, bufmodsize, lpBufMods, bufmodsize, &bRead, NULL)))
			break;

		
		PRTL_PROCESS_MODULES pm = (PRTL_PROCESS_MODULES)lpBufMods;
		PRTL_PROCESS_MODULE_INFORMATION pMod = pm->Modules;
		#define bufsize 1024
		if (!(lpBuffer = malloc(bufsize)))
			break;
		if (!(lpBufWrite = malloc(bufsize)))
			break;
		lpBufferReal = VirtualAlloc(NULL, 1, MEM_COMMIT, PAGE_READWRITE);
		#define bufrealsize 1024
		if (!(lpBufferReal = malloc(bufrealsize)))
			break;
		

		for (i = 0; i < pm->NumberOfModules; i++)
		{
			printf("%p = %-50s ", pMod[i].ImageBase, pMod[i].FullPathName);
			t = (PPA)lpBuffer;
			t->address.QuadPart = pMod[i].ImageBase;
			t->len = 256;
			if (!(DeviceIoControl(hDevice, IOCTL_READ_KERNEL_MEM, lpBuffer, bufsize, lpBuffer, bufsize, &bRead, NULL)))
				printf(" [FALLO]\n");
			else
			{
				printf(" [leeido]");
				PPAWrite = (PPA)lpBufWrite;
				PPAWrite->address.QuadPart = pMod[i].ImageBase;
				PPAWrite->len = 256;
				memcpy(&PPAWrite->buffer, lpBuffer, 256);
				if (!(DeviceIoControl(hDevice, IOCTL_WRITE_KERNEL_MEM, lpBufWrite, bufsize, lpBufWrite, bufsize, &bRead, NULL)))
				{
					printf(" [FALLO]");
				}
				else
				{
					printf(" [ESCRITO]");

				}
			}
			if ((DeviceIoControl(hDevice, IOCTL_GET_PHYSADDR, &pMod[i].ImageBase, sizeof(ULONGLONG), lpBufferReal, bufrealsize, &bRead, NULL)))
			{
				t = (PPA)lpBufferReal;
				t->len = 256;
				if ((DeviceIoControl(hDevice, IOCTL_READ_PHYS_MEM, lpBufferReal, bufrealsize, lpBufferReal, bufrealsize, &bRead, NULL)))
				{
					if (!memcmp(lpBufferReal, lpBuffer, 256))
					{
						printf(" *** Verificado ***\n");
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
		if (!(DeviceIoControl(hDevice, IOCTL_READ_KERNEL_MEM, lpBuffer, bufsize, lpBuffer, bufsize, &bRead, NULL)))
			break;
		
		ULONGLONG addr = direccion.address.QuadPart;
		if (!(DeviceIoControl(hDevice, IOCTL_GET_PHYSADDR, &addr, sizeof(ULONGLONG), lpBuffer, bufsize, &bRead, NULL)))
			break;
		
		t = (PPA)lpBuffer;
		//t->address.HighPart = 0;
		//t->address.LowPart = 0x02a1d013;
		t->len = 256;
		if (!(DeviceIoControl(hDevice, IOCTL_READ_PHYS_MEM, lpBuffer, bufsize, lpBuffer, bufsize, &bRead, NULL)))
			break;
		
		t = (PPA)lpBuffer;
		t->address.HighPart = 0;
		t->address.LowPart = 0x02a1d013;
		t->len = 5;
		strcpy(&t->buffer, "abel1");
		if (!(DeviceIoControl(hDevice, IOCTL_WRITE_PHYS_MEM, lpBuffer, bufsize, lpBuffer, bufsize, &bRead, NULL)))
			break;
		printf("[ok] GetDriverInfo: Resultado = %s \n", lpBuffer);
		Status = NO_ERROR;

	} while (FALSE);
	if (Status != NO_ERROR)
	{
		Status = GetLastError();
		printf("[x] GetDriverInfo: Error %x\n", Status);
	}
	if (lpBuffer)
		free(lpBuffer);
	if (hDevice != INVALID_HANDLE_VALUE)
		CloseHandle(hDevice);
}
int test()
{
	printf("Ruta del dispositivo: %S\n", strDeviceName);
	if (IsDriverPresent() == TRUE)
	{
		printf("[ok] IsDriverPresent: Driver localizado.\n");
		GetDriverInfo();

	}
	else
		printf("[x] !!! Error driver no localizado.\n");

}
int main()
{
	test();
	return 0;
}
