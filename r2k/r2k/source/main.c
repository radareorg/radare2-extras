// SkUaTeR 2016 
#include "common.h"
#include <Ntstrsafe.h>

static PVOID g_KernelBase = NULL;
static ULONG g_KernelSize = 0;

unsigned char getPrintChar(unsigned char ch) {
	if (isprint(ch)) {
		return ch;
	}
	return '.';
}

void DumpBuffer(PCHAR Buffer, int siz) {
	int i;
	for (i = 0; i + 15 < siz; i += 15) {
		DbgPrint ("%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\t%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c\n",
			 (unsigned char)Buffer[i], (unsigned char)Buffer[i + 1], (unsigned char)Buffer[i + 2], (unsigned char)Buffer[i + 3],
			 (unsigned char)Buffer[i + 4], (unsigned char)Buffer[i + 5], (unsigned char)Buffer[i + 6], (unsigned char)Buffer[i + 7],
			 (unsigned char)Buffer[i + 8], (unsigned char)Buffer[i + 9], (unsigned char)Buffer[i + 10], (unsigned char)Buffer[i + 11],
			 (unsigned char)Buffer[i + 12], (unsigned char)Buffer[i + 13], (unsigned char)Buffer[i + 14], (unsigned char)Buffer[i + 15],
			 getPrintChar(Buffer[i]), getPrintChar(Buffer[i + 1]), getPrintChar(Buffer[i + 2]), getPrintChar(Buffer[i + 3]),
			 getPrintChar(Buffer[i + 4]), getPrintChar(Buffer[i + 5]), getPrintChar(Buffer[i + 6]), getPrintChar(Buffer[i + 7]),
			 getPrintChar(Buffer[i + 8]), getPrintChar(Buffer[i + 9]), getPrintChar(Buffer[i + 10]), getPrintChar(Buffer[i + 11]),
			 getPrintChar(Buffer[i + 12]), getPrintChar(Buffer[i + 13]), getPrintChar(Buffer[i + 14]), getPrintChar(Buffer[i + 15])
			 );
	}
}

PVOID GetKernelBase(OUT PULONG pSize) {
	NTSTATUS status = STATUS_SUCCESS;
	ULONG bytes = 0;
	PRTL_PROCESS_MODULES pMods = NULL;
	PVOID checkPtr = NULL;
	UNICODE_STRING routineName;
	ULONG i;
	// Already found
	if (g_KernelBase != NULL) {
		if (pSize) {
			*pSize = g_KernelSize;
		}
		return g_KernelBase;
	}
	RtlUnicodeStringInit (&routineName, L"NtOpenFile");
	checkPtr = MmGetSystemRoutineAddress (&routineName);
	if (!checkPtr) {
		return NULL;
	}
	status = ZwQuerySystemInformation (SystemModuleInformation, 0, bytes, &bytes);
	if (bytes == 0)
		return NULL;
	pMods = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag (NonPagedPool, bytes, 'domP');
	RtlZeroMemory (pMods, bytes);
	status = ZwQuerySystemInformation (SystemModuleInformation, pMods, bytes, &bytes);
	if (NT_SUCCESS(status)) {
		PRTL_PROCESS_MODULE_INFORMATION pMod = pMods->Modules;
		for (i = 0; i < pMods->NumberOfModules; i++) {
			if (checkPtr >= pMod[i].ImageBase &&
				checkPtr < (PVOID)((PUCHAR)pMod[i].ImageBase + pMod[i].ImageSize)) {
				g_KernelBase = pMod[i].ImageBase;
				g_KernelSize = pMod[i].ImageSize;
				if (pSize) {
					*pSize = g_KernelSize;
				}
			}
		}
	}
	if (pMods)
		ExFreePoolWithTag (pMods, 'domP');
	return g_KernelBase;
}

NTSTATUS OnDriverDeviceControl(IN PDEVICE_OBJECT DeviceObject,IN PIRP Irp) {
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PIO_STACK_LOCATION IrpSp;
	ULONG ControlCode = 0;
	ULONG dwBytesWritten = 0;
	PCHAR pInBuf = NULL, pOutBuf = NULL;
	KAFFINITY affinity = 0;
	UNREFERENCED_PARAMETER(DeviceObject);
	IrpSp = IoGetCurrentIrpStackLocation(Irp);
	ControlCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;
	affinity = KeQueryActiveProcessors();
	Irp->IoStatus.Information = 0;
	switch (ControlCode) {
	case IOCTL_GET_SYSTEM_MODULES:
	{
		ULONG bytes = 0;
		PRTL_PROCESS_MODULES pMods = NULL;
		DbgPrint ("[R2K]  IOCTL_GET_SYSTEM_MODULES\n");
		if (!Irp->AssociatedIrp.SystemBuffer) {
			DbgPrint ("[R2K] IOCTL_GET_SYSTEM_MODULES ERROR: STATUS_INVALID_PARAMETER\n");
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		pInBuf = Irp->AssociatedIrp.SystemBuffer;
		pOutBuf = Irp->AssociatedIrp.SystemBuffer;
		Status = ZwQuerySystemInformation (SystemModuleInformation, 0, bytes, &bytes);
		if (bytes == 0) {
			DbgPrint ("[R2K] IOCTL_GET_SYSTEM_MODULES ERROR: Invalid SystemModuleInformation size\n");
			Status = STATUS_UNSUCCESSFUL;
			break;
		}
		if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < bytes) {
			DbgPrint ("[R2K] IOCTL_GET_SYSTEM_MODULES ERROR: STATUS_BUFFER_TOO_SMALL\n");
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		pMods = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag (NonPagedPool, bytes, 'domP');
		RtlZeroMemory(pMods, bytes);
		Status = ZwQuerySystemInformation (SystemModuleInformation, pMods, bytes, &bytes);
		RtlCopyMemory (pOutBuf, (void*)pMods, bytes);
		if (pMods)
			ExFreePoolWithTag (pMods, 'domP');
		dwBytesWritten = bytes;
		Status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_READ_KERNEL_MEM:
	{
		UINT32 len = 0;
		LARGE_INTEGER virt_addr = { 0x0, 0x0 };
		if (!Irp->AssociatedIrp.SystemBuffer || IrpSp->Parameters.DeviceIoControl.InputBufferLength < 3 * sizeof(UINT32)) {
			DbgPrint ("[R2K] IOCTL_READ_KERNEL_MEM ERROR: STATUS_INVALID_PARAMETER\n");
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		pInBuf = Irp->AssociatedIrp.SystemBuffer;
		pOutBuf = Irp->AssociatedIrp.SystemBuffer;
		virt_addr.LowPart = ((UINT32*)pInBuf)[0];
		virt_addr.HighPart = ((UINT32*)pInBuf)[1];
		len = ((UINT32*)pInBuf)[2];
		if (!len) 
			len = 4;
		if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < len) {
			DbgPrint ("[R2K] IOCTL_READ_KERNEL_MEM  ERROR: STATUS_BUFFER_TOO_SMALL\n");
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		__try  {
			// is addres + len valid page?
			if (!MmIsAddressValid ((void*)(LONG_PTR)(virt_addr.QuadPart + len))) {
				DbgPrint ("[R2K] IOCTL_READ_KERNEL_MEM: Error page not valid at addres + len %p\n", (virt_addr.QuadPart + len));
				Status = STATUS_ACCESS_DENIED;
				break;
			}
			if (MmIsAddressValid ((void*)(LONG_PTR)virt_addr.QuadPart)) {
				DbgPrint ("[R2K] IOCTL_READ_KERNEL_MEM: Reading address: %p\n", virt_addr.QuadPart);
				DbgPrint ("                             Bytes to read  : %u\n", len);
				RtlCopyMemory (pOutBuf, (void*)(LONG_PTR)virt_addr.QuadPart, len);
				Status = STATUS_SUCCESS;
			}
			else {
				DbgPrint ("[R2K] IOCTL_READ_KERNEL_MEM: Error page not valid %p\n", virt_addr.QuadPart);
				Status = STATUS_ACCESS_DENIED;
				break;
			}
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			Status = GetExceptionCode ();
			DbgPrint ("[R2K] IOCTL_READ_KERNEL_MEM ERROR: exception code 0x%X\n", Status);
			break;
		}
		if (NT_SUCCESS (Status)) {
			dwBytesWritten = len;
		}
		break;
	}
	case IOCTL_WRITE_KERNEL_MEM:
	{
		UINT32 len = 0;
		LARGE_INTEGER virt_addr = { 0x0, 0x0 };
		unsigned char* buffer = 0;
		if (!Irp->AssociatedIrp.SystemBuffer || IrpSp->Parameters.DeviceIoControl.InputBufferLength < 4 * sizeof(UINT32)) {
			DbgPrint ("[R2K] IOCTL_WRITE_KERNEL_MEM ERROR: STATUS_INVALID_PARAMETER\n");
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		pInBuf = Irp->AssociatedIrp.SystemBuffer;
		pOutBuf = Irp->AssociatedIrp.SystemBuffer;
		virt_addr.LowPart = ((UINT32*)pInBuf)[0];
		virt_addr.HighPart = ((UINT32*)pInBuf)[1];
		len = ((UINT32*)pInBuf)[2];
		buffer = (unsigned char *)&((UINT32*)pInBuf)[3];
		if ((IrpSp->Parameters.DeviceIoControl.InputBufferLength - (4 * sizeof(UINT32))) < len) {
			DbgPrint ("[R2K] IOCTL_WRITE_KERNEL_MEM ERROR: buffer smaller than specified\n");
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		__try {
			// is addres + len valid page?
			if (!MmIsAddressValid ((void*)(LONG_PTR)(virt_addr.QuadPart + len))) {
				DbgPrint ("[R2K] IOCTL_WRITE_KERNEL_MEM: Error page not valid at addres + len %p\n", (virt_addr.QuadPart + len));
				Status = STATUS_ACCESS_DENIED;
				break;
			}
			if (MmIsAddressValid ((void*)(LONG_PTR)virt_addr.QuadPart)) {
				DbgPrint ("[R2K] IOCTL_WRITE_KERNEL_MEM: Writing address: %p\n", virt_addr.QuadPart);
				DbgPrint ("                              Bytes to Write : %u\n", len);
				RtlCopyMemory ((void*)(LONG_PTR)virt_addr.QuadPart, (void*)buffer, len);
				Status = STATUS_SUCCESS;
			} else {
				DbgPrint ("[R2K] IOCTL_WRITE_KERNEL_MEM: Error page not valid %p\n", virt_addr.QuadPart);
				Status = STATUS_ACCESS_DENIED;
				break;
			}
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			Status = GetExceptionCode ();
			DbgPrint ("[R2K] IOCTL_READ_KERNEL_MEM ERROR: exception code 0x%X\n", Status);
			break;
		}
		if (NT_SUCCESS(Status)) {
			dwBytesWritten = len;
		}
		break;
	}
	case IOCTL_READ_PHYS_MEM:
	{
		UINT32 len = 0;
		PHYSICAL_ADDRESS phys_addr = { 0x0, 0x0 };
		DbgPrint ("[R2K]  IOCTL_READ_PHYS_MEM\n");
		if (!Irp->AssociatedIrp.SystemBuffer ||	IrpSp->Parameters.DeviceIoControl.InputBufferLength < 3 * sizeof(UINT32)) {
			DbgPrint ("[R2K] IOCTL_READ_PHYS_MEM ERROR: STATUS_INVALID_PARAMETER\n");
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		pInBuf = Irp->AssociatedIrp.SystemBuffer;
		pOutBuf = Irp->AssociatedIrp.SystemBuffer;
		phys_addr.LowPart = ((UINT32*)pInBuf)[0];
		phys_addr.HighPart = ((UINT32*)pInBuf)[1];
		len = ((UINT32*)pInBuf)[2];
		if (!len) len = 4;
		if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < len) {
			DbgPrint ("[R2K] IOCTL_READ_PHYS_MEM  ERROR: STATUS_BUFFER_TOO_SMALL\n");
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		__try {
			void * va = MmMapIoSpace (phys_addr, len, MmCached);
			if (!va) {
				DbgPrint ("[R2K] IOCTL_READ_PHYS_MEM ERROR: no space for mapping\n");
				return STATUS_UNSUCCESSFUL;
			}
			DbgPrint ("[R2K] IOCTL_READ_PHYS_MEM reading %d bytes from physical address 0x%08x_%08x (virtual = %p)", len, phys_addr.HighPart, phys_addr.LowPart, va);
			RtlCopyMemory (pOutBuf, va, len);
			MmUnmapIoSpace (va, len);
			Status = STATUS_SUCCESS;
		
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			Status = GetExceptionCode ();
			DbgPrint ("[R2K] IOCTL_READ_PHYS_MEM ERROR: exception code 0x%X\n", Status);
			break;
		}
		if (NT_SUCCESS(Status)) {
			DbgPrint ("[R2K] IOCTL_READ_PHYS_MEM Contents:\n");
			//DumpBuffer((unsigned char *)pOutBuf, min(len, 0x100));
			dwBytesWritten = len;
		}
		break;
	}
	case IOCTL_WRITE_PHYS_MEM:
	{
		UINT32 len = 0;
		PHYSICAL_ADDRESS phys_addr = { 0x0, 0x0 };
		DbgPrint ("[R2K] IOCTL_WRITE_PHYS_MEM\n");
		if (Irp->AssociatedIrp.SystemBuffer) {
			pInBuf = Irp->AssociatedIrp.SystemBuffer;
			pOutBuf = Irp->AssociatedIrp.SystemBuffer;
			if (IrpSp->Parameters.DeviceIoControl.InputBufferLength < 3 * sizeof(UINT32)) {
				DbgPrint ("[R2K] IOCTL_WRITE_PHYS_MEM ERROR: STATUS_INVALID_PARAMETER\n");
				Status = STATUS_INVALID_PARAMETER;
				break;
			}
			phys_addr.LowPart = ((UINT32*)pInBuf)[0];
			phys_addr.HighPart = ((UINT32*)pInBuf)[1];
			len = ((UINT32*)pInBuf)[2];
			pInBuf = (PCHAR)(((UINT32*)pInBuf) + 3);
			if (IrpSp->Parameters.DeviceIoControl.InputBufferLength < len + 3 * sizeof(UINT32)) {
				DbgPrint ("[R2K] IOCTL_WRITE_PHYS_MEM ERROR: STATUS_INVALID_PARAMETER\n");
				Status = STATUS_INVALID_PARAMETER;
				break;
			}
			__try {
				void * va = MmMapIoSpace (phys_addr, len, MmCached);
				if (!va) {
					DbgPrint ("[R2K] IOCTL_WRITE_PHYS_MEM ERROR: no space for mapping\n");
					return STATUS_UNSUCCESSFUL;
				}
				//DbgPrint("[R2K] IOCTL_WRITE_PHYS_MEM writing %d bytes to physical address 0x%08x_%08x (virtual = %#010x)", len, phys_addr.HighPart, phys_addr.LowPart, (unsigned int)va);
				RtlCopyMemory (va, pInBuf, len);
				MmUnmapIoSpace (va, len);
				Status = STATUS_SUCCESS;
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				Status = GetExceptionCode ();
				DbgPrint ("[R2K] IOCTL_WRITE_PHYS_MEM ERROR: exception code 0x%X\n", Status);
			}
		}
		break;
	}
	case IOCTL_GET_PHYSADDR:
	{
		UINT64 va = 0x0;
		PHYSICAL_ADDRESS pa = { 0x0, 0x0 };
		pInBuf = Irp->AssociatedIrp.SystemBuffer;
		pOutBuf = Irp->AssociatedIrp.SystemBuffer;
		DbgPrint ("[R2K] IOCTL_GET_PHYSADDR\n");
		if (!Irp->AssociatedIrp.SystemBuffer ||
			IrpSp->Parameters.DeviceIoControl.InputBufferLength != sizeof(UINT64)) {
			DbgPrint ("[R2K] IOCTL_GET_PHYSADDR ERROR: STATUS_INVALID_PARAMETER\n");
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(UINT64)) {
			DbgPrint ("[R2K] IOCTL_GET_PHYSADDR ERROR: STATUS_BUFFER_TOO_SMALL\n");
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		RtlCopyBytes (&va, (unsigned char*)Irp->AssociatedIrp.SystemBuffer, sizeof(UINT64));
		pa = MmGetPhysicalAddress ((PVOID)(ULONG_PTR)va);
		DbgPrint ("[R2K] IOCTL_GET_PHYSADDR Traslated virtual address 0x%I64X to physical: 0x%I64X\n", va, pa.QuadPart, pa.LowPart);
		RtlCopyBytes (Irp->AssociatedIrp.SystemBuffer, (void*)&pa, sizeof(UINT64));
		IrpSp->Parameters.Read.Length = sizeof(UINT64);
		dwBytesWritten = IrpSp->Parameters.Read.Length;
		Status = STATUS_SUCCESS;
		break;
	}
	default:
		Status = STATUS_NOT_SUPPORTED;
		break;
	}
	KeSetSystemAffinityThread (affinity);
	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = dwBytesWritten;
	IoCompleteRequest (Irp, IO_NO_INCREMENT);
	return Status;
}

VOID onDriverUnload(IN PDRIVER_OBJECT DriverObject) {
	NTSTATUS Status;
	UNICODE_STRING DosDeviceName;
	DbgPrint ("[R2K] onDriverUnload \n");
	RtlInitUnicodeString (&DosDeviceName, DOS_DEVICE_NAME);
	Status = IoDeleteSymbolicLink (&DosDeviceName);
	if (!NT_SUCCESS(Status)) {
		DbgPrint ("[R2K] Error: IoDeleteSymbolicLink failed\n");
	}
	if (DriverObject->DeviceObject) {
		IoDeleteDevice (DriverObject->DeviceObject);
	}
	return;
}

NTSTATUS onDriverClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
	DbgPrint ("[R2K] onDriverClose\n");
	UNREFERENCED_PARAMETER (DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return (STATUS_SUCCESS);
}

NTSTATUS onDriverOpen(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
	DbgPrint("[R2K] onDriverOpen\n");
	UNREFERENCED_PARAMETER (DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = FILE_OPENED;
	IoCompleteRequest (Irp, IO_NO_INCREMENT);
	return (STATUS_SUCCESS);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	PDEVICE_OBJECT DeviceObject = NULL;
	NTSTATUS Status = STATUS_SUCCESS;
	UNICODE_STRING DeviceName;
	UNICODE_STRING DosDeviceName;
	UNREFERENCED_PARAMETER (RegistryPath);
	RtlInitUnicodeString (&DeviceName, NT_DEVICE_NAME);
	Status = IoCreateDeviceSecure (DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL, NULL, &DeviceObject);
	if (!NT_SUCCESS(Status)) {
		DbgPrint ("[R2K] Error: IoCreateDeviceSecure failed (status = %d)\n", Status);
		return Status;
	}
	RtlInitUnicodeString (&DosDeviceName, DOS_DEVICE_NAME);
	Status = IoCreateSymbolicLink (&DosDeviceName, &DeviceName);
	if (!NT_SUCCESS(Status)) {
		DbgPrint ("[R2K] Error:  IoCreateSymbolicLink failed (status = %d)\n", Status);
		if (DeviceObject) {
			IoDeleteDevice (DeviceObject);
		}
		return Status;
	}
	DriverObject->MajorFunction[IRP_MJ_CREATE] = onDriverOpen;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = onDriverClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OnDriverDeviceControl;
	DriverObject->DriverUnload = onDriverUnload;
	return STATUS_SUCCESS;
}
