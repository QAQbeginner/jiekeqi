#include "pch.h"
#include "CTool.h"
#include"lz4.h"
#include"resource.h"

// 用于寻找区段
PIMAGE_SECTION_HEADER CTool::FindSection(PIMAGE_NT_HEADERS NtHeader, LPCSTR SectionName)
{
	auto FirstSection = IMAGE_FIRST_SECTION(NtHeader);
	for (int i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
	{
		if (strcmp((char*)FirstSection[i].Name, SectionName) == 0)
			return &FirstSection[i];
	}
	return (PIMAGE_SECTION_HEADER)FALSE;
}
// 用于报错
VOID CTool::SetError(LPCWSTR ErrorInfo)
{
	MessageBox(NULL, L"错误", ErrorInfo, NULL);
	ExitProcess(-1);
}
// 用于计算对齐后的大小
DWORD CTool::GetAligMent(DWORD Size, DWORD AligMent)
{
	return Size % AligMent == 0 ? Size : (Size / AligMent + 1) * AligMent;
}
// 获取NT头
PIMAGE_NT_HEADERS CTool::GetNtHeader(ULONG_PTR FileBase)
{
	DWORD NtHeader = PIMAGE_DOS_HEADER(FileBase)->e_lfanew + (DWORD)FileBase;
	return PIMAGE_NT_HEADERS(NtHeader);
}
// 打开指定PE文件，申请空间，获取文件内容
BOOL CTool::OpenPE(LPCWSTR FileName, ULONG_PTR& FileBase)
{
	// 打开文件
	HANDLE hFile = CreateFile(FileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		SetError(L"打开文件失败");
	// 获取文件大小
	DWORD FileSize = GetFileSize(hFile, NULL);
	// 申请空间
	FileBase = (ULONG_PTR)malloc(FileSize);
	// 将文件中的内容读取到申请的空间中
	DWORD RealSize = 0;
	if (!ReadFile(hFile, (LPVOID)FileBase, FileSize, &RealSize, NULL))
		SetError(L"读取文件失败");
	PIMAGE_NT_HEADERS NtHeader = GetNtHeader(FileBase);
	// 判断是否为PE文件
	if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
		SetError(L"PE文件格式错误");
	if (PIMAGE_DOS_HEADER((DWORD)FileBase)->e_magic != IMAGE_DOS_SIGNATURE)
		SetError(L"PE文件格式错误");
	CloseHandle(hFile);
	return TRUE;
}
// 获取区段数量，并在区段的最后添加自己的区段[要改]
BOOL CTool::CopySection(LPCSTR SectionName, ULONG_PTR& FileBase, DWORD& FileSize, PIMAGE_NT_HEADERS DllNtHeader)
{
	// 获取Dos头
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)FileBase;
	// 获取Nt头
	PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)(FileBase + DosHeader->e_lfanew);
	// 获取区段数量
	DWORD SectionNumber = NtHeader->FileHeader.NumberOfSections;
	// 获取区段
	auto FirstSection = IMAGE_FIRST_SECTION(NtHeader);
	// 获取最后一个区段
	auto LastSection = &FirstSection[SectionNumber - 1];
	// 区段数量加一
	NtHeader->FileHeader.NumberOfSections += 1;
	// 定义新区段
	auto NewSection = LastSection + 1;
	// 获取Dll中的.test段并进行拷贝
	memcpy(NewSection, FindSection(DllNtHeader, ".text"), sizeof(IMAGE_SECTION_HEADER));
	/*
	设置新区段属性
	*/
	// 区段名字
	strcpy_s((char*)NewSection->Name, 8, SectionName);

	// 区段RVA地址=原本最后一个区段的首地址加上最后一个区段的内存对齐大小
	NewSection->VirtualAddress = LastSection->VirtualAddress + GetAligMent(LastSection->Misc.VirtualSize, NtHeader->OptionalHeader.SectionAlignment);
	// 区段属性设置为可读可写可执行
	NewSection->Characteristics = 0xE00000E0;
	// 设置区段的FOA=最后一个区段的FOA+最后一个区段的文件对齐大小
	NewSection->PointerToRawData = LastSection->PointerToRawData + GetAligMent(LastSection->Misc.VirtualSize, NtHeader->OptionalHeader.FileAlignment);


	// 重新设置文件大小
	DWORD jiSize = NtHeader->OptionalHeader.SizeOfImage + NewSection->SizeOfRawData;
	NtHeader->OptionalHeader.SizeOfImage = NewSection->VirtualAddress + NewSection->Misc.VirtualSize;

	// 重新申请内存，将修改好的PE文件写进去
	FileSize = NewSection->PointerToRawData + NewSection->SizeOfRawData;
	FileBase = (ULONG_PTR)realloc((PVOID)FileBase, FileSize);
	return TRUE;
}
// 将内存写入文件
BOOL CTool::ChangeFile(LPCWSTR FileName, ULONG_PTR& FileBase, DWORD FileSize)
{
	HANDLE hFile = CreateFile(FileName, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		SetError(L"写入文件时文件打开失败");
	DWORD RealSize = 0;
	if (!WriteFile(hFile, (LPVOID)FileBase, FileSize, &RealSize, NULL))
		SetError(L"写入文件时写入文件失败");
	CloseHandle(hFile);
	MessageBox(NULL, NULL, L"加壳成功", NULL);
	ExitProcess(0);
	return TRUE;
}
// 加载生成的壳代码dll
VOID CTool::LoadShellCode(HMODULE& DllHandle, LPCWSTR FileName, DWORD& StartRVA, PSHARE_DATA& sharedata, PPACK_DATA& packdata, PRELOC_DATA& relocdata)
{
	// 加载模块
	// 获取模块中start运行函数的位置
	// 获取start的相对偏移
	// 获取用于存放数据的sharedata位置
	DllHandle = LoadLibraryEx(FileName, DllHandle, DONT_RESOLVE_DLL_REFERENCES);
	if (DllHandle == NULL)
		SetError(L"加载壳代码模块失败");
	DWORD StartAddr = (DWORD)GetProcAddress(DllHandle, "Start");
	if (StartAddr == NULL)
		SetError(L"获取函数Start失败");
	// 获取Dos头
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllHandle;
	// 获取Nt头
	PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)(DosHeader->e_lfanew + (DWORD)DllHandle);
	// 获取start的相对偏移
	PIMAGE_SECTION_HEADER TestSection = FindSection(NtHeader, ".text");
	StartRVA = StartAddr - (DWORD)DllHandle - TestSection->VirtualAddress;
	// 获取Dll中存放结构体的地址
	sharedata = (PSHARE_DATA)GetProcAddress(DllHandle, "share_data");
	if (sharedata == NULL)
		SetError(L"获取结构体sharedata失败");
	// 获取Dll中存放压缩文件数据的地址
	packdata = (PPACK_DATA)GetProcAddress(DllHandle, "pack_data");
	if (packdata == NULL)
		SetError(L"获取结构体packdata失败");
	relocdata = (PRELOC_DATA)GetProcAddress(DllHandle, "reloc_data");
	if (relocdata == NULL)
		SetError(L"获取结构体relocdata失败");
}
// 设置新的OEP
VOID CTool::SetOEP(PSHARE_DATA& sharedata, PIMAGE_NT_HEADERS FileNtHeader, DWORD FileBase, DWORD StartRVA)
{
	// 保存源程序的OEP
	// 将新添加区段的首地址
	sharedata->OldOep = FileNtHeader->OptionalHeader.AddressOfEntryPoint;
	FileNtHeader->OptionalHeader.AddressOfEntryPoint = FindSection(FileNtHeader, ".Wang")->VirtualAddress + StartRVA;
}
// 初始化函数，用于获取两个文件的Nt头
VOID CTool::InitNtHeader(PIMAGE_NT_HEADERS& FileNtHeader, PIMAGE_NT_HEADERS& DllNtHeader, DWORD FileBase, HMODULE DllHandle)
{
	PIMAGE_DOS_HEADER FileDosHeader = (PIMAGE_DOS_HEADER)FileBase;
	FileNtHeader = (PIMAGE_NT_HEADERS)(FileDosHeader->e_lfanew + FileBase);
	PIMAGE_DOS_HEADER DllDosHeader = (PIMAGE_DOS_HEADER)DllHandle;
	DllNtHeader = (PIMAGE_NT_HEADERS)(DllDosHeader->e_lfanew + (DWORD)DllHandle);
}
// 修复重定位表
VOID CTool::FixReloc(PIMAGE_NT_HEADERS& FileNtHeader, PIMAGE_NT_HEADERS DllNtHeader, HMODULE DllHandle, DWORD FileBase)
{
	// 遍历可代码dll的重定位表，并进行手动修复
	// 修复后的地址=相对偏移+加壳程序的加载基址+区段.Wang的RVA
	// 相对偏移=重定位表中保存的地址-Dll的加载基址-dll中.test的RVA
	PIMAGE_BASE_RELOCATION DllReloc = (PIMAGE_BASE_RELOCATION)(DllNtHeader->OptionalHeader.DataDirectory[5].VirtualAddress + (DWORD)DllHandle);
	while (DllReloc->SizeOfBlock != 0)
	{
		DWORD Count = (DllReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
		// 定义结构体
		typedef struct TypeOffset
		{
			WORD Offset : 12;
			WORD Type : 4;
		}TypeOffset, * PTypeOffset;
		// 获取第一个重定位项
		PTypeOffset RelocItem = (PTypeOffset)((DWORD)DllReloc + sizeof(IMAGE_BASE_RELOCATION));
		DWORD OldProtect = 0;

		for (int i = 0; i < Count; i++)
		{
			// 如果重定位类型为3：重定位指向的整个地址都需要修正。就进行修复。
			if ((RelocItem + i)->Type == 3)
			{
				DWORD* address = (DWORD*)((DWORD)DllHandle + (RelocItem + i)->Offset + DllReloc->VirtualAddress);
				// 先算相对偏移
				DWORD RelativeOffset = *address - (DWORD)DllHandle - FindSection(DllNtHeader, ".text")->VirtualAddress;
				VirtualProtect(address, 4, PAGE_EXECUTE_READWRITE, &OldProtect);
				// 再加起来，算修正后的重定位地址
				*address = RelativeOffset + FileNtHeader->OptionalHeader.ImageBase + FindSection(FileNtHeader, ".Wang")->VirtualAddress;
				// 恢复内存属性
				VirtualProtect(address, 4, OldProtect, &OldProtect);
			}
		}
		// 下一个重定位块
		DllReloc = (PIMAGE_BASE_RELOCATION)((DWORD)DllReloc + DllReloc->SizeOfBlock);
	}
	// 关闭:(& ~标志位)    开启:(|标志位)
	// FileNtHeader->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
}
// 拷贝区段内容到加壳程序中新增的区段
VOID CTool::CopySectionData(PIMAGE_NT_HEADERS& FileNtHeader, PIMAGE_NT_HEADERS DllNtHeader, DWORD FileBase, HMODULE DllHandle)
{
	// 获取加壳程序中新增添的区段
	// 获取壳代码中的.test段
	// 修改内存属性
	// 进行拷贝内容
	// 还原内存属性
	auto FileSection = FindSection(FileNtHeader, ".Wang");
	PVOID FileBuffer = (PVOID)(FileSection->PointerToRawData + FileBase);
	auto DllSection = FindSection(DllNtHeader, ".text");
	PVOID DllBuffer = (PVOID)(DllSection->VirtualAddress + (DWORD)DllHandle);

	DWORD OldProtect = 0;
	// VirtualProtect((LPVOID)(FileSection->VirtualAddress + FileBase), 0x1000,PAGE_EXECUTE_READWRITE, &OldProtect);
	memcpy(FileBuffer, DllBuffer, FileSection->Misc.VirtualSize);
	// VirtualProtect((LPVOID)(FileSection->VirtualAddress + FileBase), 0x1000, OldProtect, &OldProtect);
}
// 加密代码段
VOID CTool::EnCodeText(PIMAGE_NT_HEADERS& FileNtHeader, DWORD FileBase, PSHARE_DATA& sharedata)
{
	// 获取加壳程序的代码区段
	// RVA转VA
	// 进行字节加密
	PIMAGE_SECTION_HEADER FileSection = FindSection(FileNtHeader, ".text");
	auto CodeBuffer = (BYTE*)(FileBase + FileSection->PointerToRawData);
	sharedata->XorStart = FileSection->VirtualAddress;
	sharedata->XorAddr = FileSection->SizeOfRawData;
	sharedata->XorKey = (rand() % 0x100);
	for (int i = 0; i < sharedata->XorAddr; i += 2)
	{
		CodeBuffer[i] ^= (sharedata->XorKey);
	}
}
// 压缩源程序
VOID CTool::PackFile(PIMAGE_NT_HEADERS& FileNtHeader, PIMAGE_NT_HEADERS& DllNtHeader, PPACK_DATA& packdata, DWORD& FileBase, DWORD& FileSize, HMODULE& DllHandle)
{
	packdata->IfPack = TRUE;
	int SecTextSize = FindSection(FileNtHeader, ".text")->SizeOfRawData;
	char* TextSecData = (char*)(FindSection(FileNtHeader, ".text")->PointerToRawData + FileBase);
	packdata->SizeOfRawData = SecTextSize;
	//被压缩的数据,Packed保存压缩数据的空间，WorkMem为完成压缩需要使用的空间
	// 申请内存空间，用于保存压缩后的数据
	char* pBuff = (char*)malloc(LZ4_compressBound(SecTextSize));
	// 开始压缩文件数据（函数返回压缩后的大小）
	int RelcompressSize = LZ4_compress(TextSecData, pBuff, SecTextSize);
	DWORD AlignSize = GetAligMent(RelcompressSize, 0x200);

	//新空间大小
	DWORD NewFileSize = FileSize - FindSection(FileNtHeader, ".text")->SizeOfRawData + AlignSize;
	//申请新的空间大小 文件大小 - 区段在文件中的大小 + 压缩后的大小(不对齐)
	DWORD NewFileBase = (DWORD)malloc(NewFileSize);
	//TextSecData之前的数据
	DWORD PreText = FindSection(FileNtHeader, ".text")->PointerToRawData - 1;
	//拷贝TextSecData段之前的数据
	memcpy((LPVOID)NewFileBase, (LPVOID)FileBase, PreText);
	//拷贝压缩部分的数据
	memcpy((LPVOID)(NewFileBase + PreText + 1), pBuff, RelcompressSize);
	//拷贝TextSecData段后面的数据
	LPVOID DestAddr = (LPVOID)(NewFileBase + PreText + AlignSize + 1);


	DWORD TextSecSize = FindSection(FileNtHeader, ".text")->SizeOfRawData;
	// DWORD TextSecPointRaw = FindSection(FileNtHeader, ".text")->PointerToRawData;
	LPVOID SrcAddr = (LPVOID)(FileBase + TextSecSize + PreText + 1);
	DWORD LastSize = NewFileSize - PreText - AlignSize;
	memcpy(DestAddr, SrcAddr, LastSize);
	//free(&FileBase);
	FileBase = NewFileBase;
	InitNtHeader(FileNtHeader, DllNtHeader, FileBase, DllHandle);
	//free((void*)NewFileBase);
	NewFileBase = NULL;
	// 1. 获取到目标模块的区段表   
	auto Sections = IMAGE_FIRST_SECTION(GetNtHeader(FileBase));

	// 2. 使用文件头中的区段数量遍历区段表   
	WORD Count = (WORD)(GetNtHeader(FileBase)->FileHeader.NumberOfSections);
	BOOL bChangeFoa = FALSE;
	for (WORD i = 0; i < Count; ++i)
	{
		if (bChangeFoa) {
			Sections[i].PointerToRawData = Sections[i].PointerToRawData - FindSection(FileNtHeader, ".text")->SizeOfRawData + AlignSize;
		}
		// 3. .text区段之前的区段不改变,操作.text区段之后的区段
		if (!_strcmpi((char*)Sections[i].Name, ".text")) {
			bChangeFoa = TRUE;
		}
	}
	packdata->FileCompressSize = RelcompressSize;
	packdata->TextRVA = FindSection(FileNtHeader, ".text")->VirtualAddress;
	FileSize = NewFileSize;
}
// 清零IAT，取消系统对IAT的操作权
VOID CTool::ZeroIAT(PIMAGE_NT_HEADERS& FileNtHeader, PSHARE_DATA& sharedata)
{
	sharedata->IATRVA = FileNtHeader->OptionalHeader.DataDirectory[1].VirtualAddress;
	FileNtHeader->OptionalHeader.DataDirectory[1].VirtualAddress = 0;
	FileNtHeader->OptionalHeader.DataDirectory[12].VirtualAddress = 0;
}
// 添加区段
VOID CTool::AddSection(LPCSTR SectionName, ULONG_PTR& FileBase, DWORD& FileSize, DWORD Size)
{
	// 获取Dos头
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)FileBase;
	// 获取Nt头
	PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)(FileBase + DosHeader->e_lfanew);
	// 获取区段数量
	DWORD SectionNumber = NtHeader->FileHeader.NumberOfSections;
	// 获取区段
	auto FirstSection = IMAGE_FIRST_SECTION(NtHeader);
	// 获取最后一个区段
	auto LastSection = &FirstSection[SectionNumber - 1];
	// 定义新区段
	auto NewSection = LastSection + 1;
	//Name
	memcpy(NewSection->Name, SectionName, 7);
	//VirtualSize
	NewSection->Misc.VirtualSize = GetAligMent(Size, NtHeader->OptionalHeader.SectionAlignment);
	//VirtualAddress = 最后一个区段的 VirtualAddress +最后一个区段内存大小
	NewSection->VirtualAddress = LastSection->VirtualAddress +
		GetAligMent(LastSection->Misc.VirtualSize, NtHeader->OptionalHeader.SectionAlignment);
	//SizeOfRawData
	NewSection->SizeOfRawData = GetAligMent(Size, NtHeader->OptionalHeader.FileAlignment);
	//PointerToRawData = 最后一个区段的 PointerToRawData + 最后一个区段文件大小
	NewSection->PointerToRawData = LastSection->PointerToRawData +
		GetAligMent(LastSection->SizeOfRawData, NtHeader->OptionalHeader.FileAlignment);
	//Characteristics
	NewSection->Characteristics = 0xE00000E0;
	// 区段数量加一
	NtHeader->FileHeader.NumberOfSections += 1;
	//SizeOfImage大小
	NtHeader->OptionalHeader.SizeOfImage += GetAligMent(NewSection->Misc.VirtualSize, NtHeader->OptionalHeader.SectionAlignment);
	//从新分配空间，将新区段添加到堆空间中
	FileSize = NewSection->SizeOfRawData + NewSection->PointerToRawData;
	FileBase = (DWORD)realloc((VOID*)FileBase, FileSize);
	// 获取Dos头
	DosHeader = (PIMAGE_DOS_HEADER)FileBase;
	// 获取Nt头
	NtHeader = (PIMAGE_NT_HEADERS)(FileBase + DosHeader->e_lfanew);
	NewSection = FindSection(NtHeader, SectionName);
	memset((DWORD*)(NewSection->PointerToRawData + FileBase), 0, NewSection->SizeOfRawData);
	return;
}
// 设置重定位表指向新增的区段
VOID CTool::SetReloc(PIMAGE_NT_HEADERS& FileNtHeader, PIMAGE_NT_HEADERS& DllNtHeader, RELOC_DATA& relocdata, ULONG_PTR& FileBase, DWORD& FileSize, HMODULE& DllHandle)
{
	// 获取加壳程序的重定位表信息
	auto FileReloc = FileNtHeader->OptionalHeader.DataDirectory[5];
	relocdata.RelocRVA = FileReloc.VirtualAddress;
	relocdata.RelocSize = FileReloc.Size;
	relocdata.ImageBase = FileNtHeader->OptionalHeader.ImageBase;
	relocdata.OldImageBase = FileNtHeader->OptionalHeader.ImageBase;
	//Dll重定位表
	auto DllBaseReloc = (PIMAGE_BASE_RELOCATION)(DllNtHeader->OptionalHeader.DataDirectory[5].VirtualAddress + (DWORD)DllHandle);
	DWORD DllRelocaSize = DllNtHeader->OptionalHeader.DataDirectory[5].Size;
	//新增区段
	AddSection(".NReloc", FileBase, FileSize, DllRelocaSize);
	InitNtHeader(FileNtHeader, DllNtHeader, FileBase, DllHandle);
	auto NewSecHed = FindSection(FileNtHeader, ".NReloc");
	auto OldSecHed = FindSection(DllNtHeader, ".text");
	auto PackSecHed = FindSection(FileNtHeader, ".Wang");
	auto NewRelocaSection = (PIMAGE_BASE_RELOCATION)(NewSecHed->PointerToRawData + FileBase);
	DWORD OldSectionAddr = (DWORD)(OldSecHed->VirtualAddress + (DWORD)DllHandle);

	memcpy((DWORD*)NewRelocaSection, (DWORD*)(DllBaseReloc), DllRelocaSize);
	while (NewRelocaSection->VirtualAddress) {
		//新的内存页起始RVA = 原RVA - 原段基址 +.pack段基址
		NewRelocaSection->VirtualAddress = NewRelocaSection->VirtualAddress - (OldSectionAddr - (DWORD)DllHandle) + PackSecHed->VirtualAddress;
		NewRelocaSection = (PIMAGE_BASE_RELOCATION)(NewRelocaSection->SizeOfBlock + (DWORD)NewRelocaSection);
	}
	//替换原程序重定位表
	FileNtHeader->OptionalHeader.DataDirectory[5].VirtualAddress = NewSecHed->VirtualAddress;
	FileNtHeader->OptionalHeader.DataDirectory[5].Size = DllRelocaSize;
}
// RVA转FOA
DWORD CTool::RvaToOffset(DWORD lpImage, DWORD dwRva)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpImage;
	PIMAGE_NT_HEADERS32 pNT32 = (PIMAGE_NT_HEADERS32)((LONG)lpImage + pDos->e_lfanew);
	PIMAGE_FILE_HEADER pFileHeader = &pNT32->FileHeader;
	PIMAGE_SECTION_HEADER pSeciton = IMAGE_FIRST_SECTION(pNT32);
	for (int i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		if (dwRva > pSeciton->VirtualAddress && dwRva < pSeciton->VirtualAddress + pSeciton->SizeOfRawData)
		{
			DWORD dwChazhi = dwRva - pSeciton->VirtualAddress;
			return pSeciton->PointerToRawData + dwChazhi;
		}
		pSeciton++;
	}
}

//备份TLS后清空TLS
VOID CTool::SetTls(PIMAGE_NT_HEADERS& FileNtHeader, ULONG_PTR& FileBase, PSHARE_DATA& sharedata)
{
	sharedata->TlsVirtualAddress = FileNtHeader->OptionalHeader.DataDirectory[9].VirtualAddress;
	if (sharedata->TlsVirtualAddress)
	{
		FileNtHeader->OptionalHeader.DataDirectory[9].VirtualAddress = 0;
		DWORD TlsFoa = RvaToOffset(FileBase, sharedata->TlsVirtualAddress);
		auto TlsTable = (PIMAGE_TLS_DIRECTORY)(TlsFoa + FileBase);
		sharedata->TlsCallBackTableVa = TlsTable->AddressOfCallBacks;
	}
}
// 将资源加入加壳程序 
 VOID CTool::AddResource(LPCWSTR FileName)
{
	// 获取指定模块里的资源
	HRSRC hRsrc = FindResource(NULL, MAKEINTRESOURCE(IDR_MYRES2), L"MYRES");
	// 获取资源大小
	DWORD dwSize = SizeofResource(NULL, hRsrc);
	// 将资源加载到内存中
	HGLOBAL hGlobal = LoadResource(NULL, hRsrc);
	// 锁定资源
	LPVOID lpVoid = LockResource(hGlobal);
	HANDLE hResource=BeginUpdateResource(FileName, FALSE);
	// 保存资源为文件	
	UpdateResource(hResource, L"MYRES",L"6666",LANG_CHINESE, lpVoid, dwSize);
	EndUpdateResource(hResource, FALSE);
}