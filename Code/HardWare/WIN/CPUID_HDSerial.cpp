#ifdef WIN32
#include <iostream>
#include <string>
#include <windows.h>
using namespace std;

// IOCTL
#if(_WIN32_WINNT < 0x0400)
#define SMART_GET_VERSION				0x00074080
#define SMART_RCV_DRIVE_DATA			0x0007c088
#endif
#define FILE_DEVICE_SCSI				0x0000001b
#define IOCTL_SCSI_MINIPORT_IDENTIFY	((FILE_DEVICE_SCSI << 16) + 0x0501)
#define IOCTL_SCSI_MINIPORT				0x0004D008

// IDEREGS
#define IDE_ATAPI_IDENTIFY		0xA1
#define IDE_ATA_IDENTIFY		0xEC
#define IDENTIFY_BUFFER_SIZE	512
#define SENDIDLENGTH			sizeof(SENDCMDOUTPARAMS) + IDENTIFY_BUFFER_SIZE

typedef struct _GETVERSIONOUTPARAMS
{
	BYTE bVersion;
	BYTE bRevision;
	BYTE bReserved;
	BYTE bIDEDeviceMap;
	DWORD fCapabilities;
	DWORD dwReserved[4];
} GETVERSIONOUTPARAMS, *PGETVERSIONOUTPARAMS, *LPGETVERSIONOUTPARAMS;

typedef struct _IDSECTOR
{
	USHORT  wGenConfig;
	USHORT  wNumCyls;
	USHORT  wReserved;
	USHORT  wNumHeads;
	USHORT  wBytesPerTrack;
	USHORT  wBytesPerSector;
	USHORT  wSectorsPerTrack;
	USHORT  wVendorUnique[3];
	CHAR    sSerialNumber[20];
	USHORT  wBufferType;
	USHORT  wBufferSize;
	USHORT  wECCSize;
	CHAR    sFirmwareRev[8];
	CHAR    sModelNumber[40];
	USHORT  wMoreVendorUnique;
	USHORT  wDoubleWordIO;
	USHORT  wCapabilities;
	USHORT  wReserved1;
	USHORT  wPIOTiming;
	USHORT  wDMATiming;
	USHORT  wBS;
	USHORT  wNumCurrentCyls;
	USHORT  wNumCurrentHeads;
	USHORT  wNumCurrentSectorsPerTrack;
	ULONG   ulCurrentSectorCapacity;
	USHORT  wMultSectorStuff;
	ULONG   ulTotalAddressableSectors;
	USHORT  wSingleWordDMA;
	USHORT  wMultiWordDMA;
	BYTE    bReserved[128];
} IDSECTOR, *PIDSECTOR;

typedef struct _SRB_IO_CONTROL
{
	ULONG HeaderLength;
	UCHAR Signature[8];
	ULONG Timeout;
	ULONG ControlCode;
	ULONG ReturnCode;
	ULONG Length;
} SRB_IO_CONTROL, *PSRB_IO_CONTROL;

#if(_WIN32_WINNT < 0x0400)
typedef struct _DRIVERSTATUS {
  UCHAR bDriverError;
  UCHAR bIDEError;
  UCHAR bReserved[2];
  ULONG dwReserved[2];
} DRIVERSTATUS, *PDRIVERSTATUS, *LPDRIVERSTATUS;

typedef struct _SENDCMDOUTPARAMS {
  ULONG        cBufferSize;
  DRIVERSTATUS DriverStatus;
  UCHAR        bBuffer[1];
} SENDCMDOUTPARAMS, *PSENDCMDOUTPARAMS, *LPSENDCMDOUTPARAMS;

typedef struct _IDEREGS {
  UCHAR bFeaturesReg;
  UCHAR bSectorCountReg;
  UCHAR bSectorNumberReg;
  UCHAR bCylLowReg;
  UCHAR bCylHighReg;
  UCHAR bDriveHeadReg;
  UCHAR bCommandReg;
  UCHAR bReserved;
} IDEREGS, *PIDEREGS, *LPIDEREGS;

typedef struct _SENDCMDINPARAMS {
  ULONG   cBufferSize;
  IDEREGS irDriveRegs;
  UCHAR   bDriveNumber;
  UCHAR   bReserved[3];
  ULONG   dwReserved[4];
  UCHAR   bBuffer[1];
} SENDCMDINPARAMS, *PSENDCMDINPARAMS, *LPSENDCMDINPARAMS;
#endif

// 获取IDE硬盘序列号(只支持Windows NT/2000/XP以上操作系统)
bool GetIDEHDSerial(int driveNum, std::string& serialNum)
{
	BYTE IdOutCmd[sizeof(SENDCMDOUTPARAMS) + IDENTIFY_BUFFER_SIZE - 1];
	bool bFlag = false;
	char driveName[32];
	HANDLE hDevice = 0;

	sprintf_s(driveName, 32, "\\\\.\\PhysicalDrive%d", driveNum);
	// 创建文件需要管理员权限
	hDevice = CreateFileA(driveName, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hDevice != INVALID_HANDLE_VALUE) {
		GETVERSIONOUTPARAMS versionParams;
		DWORD bytesReturned = 0;
		// 得到驱动器的IO控制器版本
		memset((void*) &versionParams, 0, sizeof(versionParams));
		if (DeviceIoControl(hDevice, SMART_GET_VERSION, NULL, 0,
			&versionParams, sizeof(versionParams), &bytesReturned, NULL))
		{        
			if (versionParams.bIDEDeviceMap > 0) {
				BYTE bIDCmd = 0;   // IDE或者ATAPI识别命令
				SENDCMDINPARAMS scip;

				// 如果驱动器是光驱，采用命令IDE_ATAPI_IDENTIFY
				// 否则采用命令IDE_ATA_IDENTIFY读取驱动器信息
				bIDCmd = (versionParams.bIDEDeviceMap >> driveNum & 0x10) ? IDE_ATAPI_IDENTIFY : IDE_ATA_IDENTIFY;
				memset(&scip, 0, sizeof(scip));
				memset(IdOutCmd, 0, sizeof(IdOutCmd));
				// 为读取设备信息准备参数
				scip.cBufferSize = IDENTIFY_BUFFER_SIZE;
				scip.irDriveRegs.bFeaturesReg = 0;
				scip.irDriveRegs.bSectorCountReg = 1;
				scip.irDriveRegs.bSectorNumberReg = 1;
				scip.irDriveRegs.bCylLowReg = 0;
				scip.irDriveRegs.bCylHighReg = 0;
				// 计算驱动器位置
				scip.irDriveRegs.bDriveHeadReg = 0xA0 | (((BYTE)driveNum & 1) << 4);
				// 设置读取命令
				scip.irDriveRegs.bCommandReg = bIDCmd;
				scip.bDriveNumber = (BYTE)driveNum;
				scip.cBufferSize = IDENTIFY_BUFFER_SIZE;

				// 读取驱动器信息
				if (DeviceIoControl(hDevice, SMART_RCV_DRIVE_DATA,
					(LPVOID)&scip, sizeof(SENDCMDINPARAMS) - 1, (LPVOID)&IdOutCmd,
					sizeof(SENDCMDOUTPARAMS) + IDENTIFY_BUFFER_SIZE - 1,
					&bytesReturned, NULL))
				{
					USHORT *pIdSector = (USHORT *)((PSENDCMDOUTPARAMS)IdOutCmd)->bBuffer;

					int nIndex = 0, nPosition = 0;
					char szSeq[32] = {0};
					for (nIndex = 10; nIndex < 20; nIndex++) {
						szSeq[nPosition] = (unsigned char)(pIdSector[nIndex] / 256);
						nPosition++;
						szSeq[nPosition] = (unsigned char)(pIdSector[nIndex] % 256);
						nPosition++;
					}
					serialNum = szSeq;
					serialNum.erase(0, serialNum.find_first_not_of(" "));
					bFlag = true;  // 读取硬盘信息成功
				} else
					cout<<"DeviceIoControl error:"<<GetLastError()<<endl;
			} else
				cout<<"bIDEDeviceMap <= 0"<<endl;
		} else
			cout<<"DeviceIoControl VERSION error:"<<GetLastError()<<endl;
		CloseHandle(hDevice);  // 关闭句柄
	} else
		cout<<"CreateFileA error:"<<GetLastError()<<endl;
	return bFlag;
}

// 获取SCSI硬盘序列号(只支持Windows NT/2000/XP以上操作系统)
bool GetSCSIHDSerial(int driveNum, std::string& serialNum)
{
	bool bFlag = false;
	int controller = driveNum;
	HANDLE hDevice = 0;
	char driveName [32];
	sprintf_s(driveName, 32, "\\\\.\\Scsi%d:", controller);
	hDevice = CreateFileA(driveName, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hDevice != INVALID_HANDLE_VALUE) {
		DWORD dummy;
		for (int drive = 0; drive < 2; drive++) {
			char buffer[sizeof(SRB_IO_CONTROL) + SENDIDLENGTH];
			SRB_IO_CONTROL *p = (SRB_IO_CONTROL *)buffer;
			SENDCMDINPARAMS *pin = (SENDCMDINPARAMS *)(buffer + sizeof(SRB_IO_CONTROL));
			// 准备参数
			memset(buffer, 0, sizeof(buffer));
			p->HeaderLength = sizeof(SRB_IO_CONTROL);
			p->Timeout = 10000;
			p->Length = SENDIDLENGTH;
			p->ControlCode = IOCTL_SCSI_MINIPORT_IDENTIFY;
			strncpy_s((char *)p->Signature, 9, "SCSIDISK", 9);
			pin->irDriveRegs.bCommandReg = IDE_ATA_IDENTIFY;
			pin->bDriveNumber = drive;
			// 得到SCSI硬盘信息
			if (DeviceIoControl(hDevice, IOCTL_SCSI_MINIPORT, buffer,
				sizeof(SRB_IO_CONTROL) + sizeof(SENDCMDINPARAMS) - 1,
				buffer, sizeof(SRB_IO_CONTROL) + SENDIDLENGTH, &dummy, NULL))
			{
				SENDCMDOUTPARAMS *pOut = (SENDCMDOUTPARAMS *)(buffer + sizeof(SRB_IO_CONTROL));
				IDSECTOR *pId = (IDSECTOR *)(pOut->bBuffer);
				if (pId->sModelNumber[0]) {
					USHORT *pIdSector = (USHORT *)pId;
					int nIndex = 0, nPosition = 0;
					char szSeq[32] = {0};
					for (nIndex = 10; nIndex < 20; nIndex++) {
						szSeq[nPosition] = (unsigned char)(pIdSector[nIndex] / 256);
						nPosition++;
						szSeq[nPosition] = (unsigned char)(pIdSector[nIndex] % 256);
						nPosition++;
					}
					serialNum = szSeq;
					serialNum.erase(0, serialNum.find_first_not_of(" "));
					bFlag = true;  // 读取硬盘信息成功
					break;
				}
			}
		}
		CloseHandle(hDevice);  // 关闭句柄
	}
	return bFlag;
}

std::string GetCPUID()
{
	std::string strCPUId;
	unsigned long s1, s2;
	char buf[32] = {0};
	
	__asm{
		mov eax,01h   //eax=1:取CPU序列号
		xor edx,edx
		cpuid
		mov s1,edx
		mov s2,eax
	}
	if (s1) {
		memset(buf, 0, 32);
		sprintf_s(buf, 32, "%08X", s1);
		strCPUId += buf;
	}
	if (s2) {
		memset(buf, 0, 32);
		sprintf_s(buf, 32, "%08X", s2);
		strCPUId += buf;
	}

	__asm{
		mov eax,03h
		xor ecx,ecx
		xor edx,edx
		cpuid
		mov s1,edx
		mov s2,ecx
	}
	if (s1) {
		memset(buf, 0, 32);
		sprintf_s(buf, 32, "%08X", s1);
		strCPUId += buf;
	}
	if (s2) {
		memset(buf, 0, 32);
		sprintf_s(buf, 32, "%08X", s2);
		strCPUId += buf;
	}
	return strCPUId;
}

int main()
{
	cout<<"CPUID:"<<GetCPUID()<<endl;
	std::string serialNum;
	for (int driveNum = 0; driveNum < 5; driveNum++) {
		if(!GetIDEHDSerial(driveNum, serialNum))
			GetSCSIHDSerial(driveNum, serialNum);
		if (!serialNum.empty())
			break;
	}
	cout<<"HardDisk serialNum:"<<serialNum<<endl;
	getchar();
	return 0;
}

#else

#include <stdio.h>
#include <sys/ioctl.h>
#include <linux/hdreg.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string>
#include <memory.h>

int getdiskid(char *hardc)
{
	int fd;
	struct hd_driveid hid;
	fd = open("/dev/sda", O_RDONLY);
	if (fd < 0) {
		return -1;
	}
	if (ioctl(fd, HDIO_GET_IDENTITY, &hid) < 0) {
		return -1;
	}
	close(fd);
	sprintf(hardc,"%s", hid.serial_no);
	return 0;
}

std::string getcpuid()
{
	std::string strCPUId;
	unsigned long s1,s2;
	char buf[32] = {0};

	asm volatile(
		"movl $0x01, %%eax;"
		"xorl %%edx, %%edx;"
		"cpuid;"
		"movl %%edx, %0;"
		"movl %%eax, %1;"
		:"=m"(s1), "=m"(s2)
	);
	if (s1) {
		memset(buf, 0, 32);
		snprintf(buf, 32, "%08X", s1);
		strCPUId += buf;
	}
	if (s2) {
		memset(buf, 0, 32);
		snprintf(buf, 32, "%08X", s2);
		strCPUId += buf;
	}

	asm volatile(
		"movl $0x03, %%eax;"
		"xorl %%ecx, %%ecx;"
		"xorl %%edx, %%edx;"
		"cpuid;"
		"movl %%edx, %0;"
		"movl %%ecx, %1;"
		:"=m"(s1), "=m"(s2)
	);
	if (s1) {
		memset(buf, 0, 32);
		snprintf(buf, 32, "%08X", s1);
		strCPUId += buf;
	}
	if (s2) {
		memset(buf, 0, 32);
		snprintf(buf, 32, "%08X", s2);
		strCPUId += buf;
	}

	return strCPUId;
}

int main(void)
{
	char hardseri[50];
	getdiskid(hardseri);
	printf("hardseri id %s\n",hardseri);

	std::string cpuid = getcpuid();
	printf("cpuid is %s\n",cpuid.c_str());
	return 0;
}

#endif
