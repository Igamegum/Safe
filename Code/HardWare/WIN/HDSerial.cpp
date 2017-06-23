#include <windows.h>
#include <stdio.h>
#include <iostream>

#define debug_msg std::cerr << __FUNCTION__ << __LINE__ << std::endl

BOOL GetHDID(PCHAR pIDBufer)

{
	HANDLE hDevice = NULL;
	hDevice = ::CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (!hDevice)

	{

		hDevice = ::CreateFileA("\\\\.\\Scsi0", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);

	}

	if (!hDevice)

	{
		debug_msg;
		return FALSE;

	}

	DWORD dwBytesReturned = 0;
	GETVERSIONINPARAMS gVersionParsams;
	ZeroMemory(&gVersionParsams, sizeof(GETVERSIONINPARAMS));


	if (!DeviceIoControl(hDevice, SMART_GET_VERSION, NULL, NULL, &gVersionParsams, sizeof(GETVERSIONINPARAMS), &dwBytesReturned, NULL)
		|| dwBytesReturned == 0 || gVersionParsams.bIDEDeviceMap <= 0)
	{
		::CloseHandle(hDevice);
		debug_msg;
		return FALSE;
	}

	SENDCMDINPARAMS scip;

	ZeroMemory(&scip, sizeof(SENDCMDINPARAMS));
	scip.cBufferSize = IDENTIFY_BUFFER_SIZE;
	scip.irDriveRegs.bSectorCountReg = 1;
	scip.irDriveRegs.bSectorNumberReg = 1;
	scip.irDriveRegs.bDriveHeadReg = 0xA0;
	scip.irDriveRegs.bCommandReg = 0xEC;

	BYTE btBuffer[1024] = { 0 };

	if (!DeviceIoControl(hDevice, SMART_RCV_DRIVE_DATA, &scip, sizeof(SENDCMDINPARAMS),
		btBuffer, 1024, &dwBytesReturned, NULL))
	{
		::CloseHandle(hDevice);
		debug_msg;
		return FALSE;
	}

	int nPos = 0x24;            //序列号的开始位置,具体请参考SENDCMDOUTPARAMS与IDSECTOR结构
	while (btBuffer[nPos]<128)
	{
		*pIDBufer = btBuffer[nPos++];
		pIDBufer++;
	}
	*pIDBufer = 00;
	return TRUE;
}

int main()
{
	CHAR szHDID[256];
	if (GetHDID(szHDID))

	{

		printf("硬盘序列号:%s\n", szHDID);

	}

	else

	{

		printf("取硬盘序列号失败");

	}

	

	return 0;
}

