#include "pch.h"
#include "CTool.h"
#include"lz4.h"
#include"resource.h"

// ����Ѱ������
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
// ���ڱ���
VOID CTool::SetError(LPCWSTR ErrorInfo)
{
	MessageBox(NULL, L"����", ErrorInfo, NULL);
	ExitProcess(-1);
}
// ���ڼ�������Ĵ�С
DWORD CTool::GetAligMent(DWORD Size, DWORD AligMent)
{
	return Size % AligMent == 0 ? Size : (Size / AligMent + 1) * AligMent;
}
// ��ȡNTͷ
PIMAGE_NT_HEADERS CTool::GetNtHeader(ULONG_PTR FileBase)
{
	DWORD NtHeader = PIMAGE_DOS_HEADER(FileBase)->e_lfanew + (DWORD)FileBase;
	return PIMAGE_NT_HEADERS(NtHeader);
}
// ��ָ��PE�ļ�������ռ䣬��ȡ�ļ�����
BOOL CTool::OpenPE(LPCWSTR FileName, ULONG_PTR& FileBase)
{
	// ���ļ�
	HANDLE hFile = CreateFile(FileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		SetError(L"���ļ�ʧ��");
	// ��ȡ�ļ���С
	DWORD FileSize = GetFileSize(hFile, NULL);
	// ����ռ�
	FileBase = (ULONG_PTR)malloc(FileSize);
	// ���ļ��е����ݶ�ȡ������Ŀռ���
	DWORD RealSize = 0;
	if (!ReadFile(hFile, (LPVOID)FileBase, FileSize, &RealSize, NULL))
		SetError(L"��ȡ�ļ�ʧ��");
	PIMAGE_NT_HEADERS NtHeader = GetNtHeader(FileBase);
	// �ж��Ƿ�ΪPE�ļ�
	if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
		SetError(L"PE�ļ���ʽ����");
	if (PIMAGE_DOS_HEADER((DWORD)FileBase)->e_magic != IMAGE_DOS_SIGNATURE)
		SetError(L"PE�ļ���ʽ����");
	CloseHandle(hFile);
	return TRUE;
}
// ��ȡ�����������������ε��������Լ�������[Ҫ��]
BOOL CTool::CopySection(LPCSTR SectionName, ULONG_PTR& FileBase, DWORD& FileSize, PIMAGE_NT_HEADERS DllNtHeader)
{
	// ��ȡDosͷ
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)FileBase;
	// ��ȡNtͷ
	PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)(FileBase + DosHeader->e_lfanew);
	// ��ȡ��������
	DWORD SectionNumber = NtHeader->FileHeader.NumberOfSections;
	// ��ȡ����
	auto FirstSection = IMAGE_FIRST_SECTION(NtHeader);
	// ��ȡ���һ������
	auto LastSection = &FirstSection[SectionNumber - 1];
	// ����������һ
	NtHeader->FileHeader.NumberOfSections += 1;
	// ����������
	auto NewSection = LastSection + 1;
	// ��ȡDll�е�.test�β����п���
	memcpy(NewSection, FindSection(DllNtHeader, ".text"), sizeof(IMAGE_SECTION_HEADER));
	/*
	��������������
	*/
	// ��������
	strcpy_s((char*)NewSection->Name, 8, SectionName);

	// ����RVA��ַ=ԭ�����һ�����ε��׵�ַ�������һ�����ε��ڴ�����С
	NewSection->VirtualAddress = LastSection->VirtualAddress + GetAligMent(LastSection->Misc.VirtualSize, NtHeader->OptionalHeader.SectionAlignment);
	// ������������Ϊ�ɶ���д��ִ��
	NewSection->Characteristics = 0xE00000E0;
	// �������ε�FOA=���һ�����ε�FOA+���һ�����ε��ļ������С
	NewSection->PointerToRawData = LastSection->PointerToRawData + GetAligMent(LastSection->Misc.VirtualSize, NtHeader->OptionalHeader.FileAlignment);


	// ���������ļ���С
	DWORD jiSize = NtHeader->OptionalHeader.SizeOfImage + NewSection->SizeOfRawData;
	NtHeader->OptionalHeader.SizeOfImage = NewSection->VirtualAddress + NewSection->Misc.VirtualSize;

	// ���������ڴ棬���޸ĺõ�PE�ļ�д��ȥ
	FileSize = NewSection->PointerToRawData + NewSection->SizeOfRawData;
	FileBase = (ULONG_PTR)realloc((PVOID)FileBase, FileSize);
	return TRUE;
}
// ���ڴ�д���ļ�
BOOL CTool::ChangeFile(LPCWSTR FileName, ULONG_PTR& FileBase, DWORD FileSize)
{
	HANDLE hFile = CreateFile(FileName, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		SetError(L"д���ļ�ʱ�ļ���ʧ��");
	DWORD RealSize = 0;
	if (!WriteFile(hFile, (LPVOID)FileBase, FileSize, &RealSize, NULL))
		SetError(L"д���ļ�ʱд���ļ�ʧ��");
	CloseHandle(hFile);
	MessageBox(NULL, NULL, L"�ӿǳɹ�", NULL);
	ExitProcess(0);
	return TRUE;
}
// �������ɵĿǴ���dll
VOID CTool::LoadShellCode(HMODULE& DllHandle, LPCWSTR FileName, DWORD& StartRVA, PSHARE_DATA& sharedata, PPACK_DATA& packdata, PRELOC_DATA& relocdata)
{
	// ����ģ��
	// ��ȡģ����start���к�����λ��
	// ��ȡstart�����ƫ��
	// ��ȡ���ڴ�����ݵ�sharedataλ��
	DllHandle = LoadLibraryEx(FileName, DllHandle, DONT_RESOLVE_DLL_REFERENCES);
	if (DllHandle == NULL)
		SetError(L"���ؿǴ���ģ��ʧ��");
	DWORD StartAddr = (DWORD)GetProcAddress(DllHandle, "Start");
	if (StartAddr == NULL)
		SetError(L"��ȡ����Startʧ��");
	// ��ȡDosͷ
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllHandle;
	// ��ȡNtͷ
	PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)(DosHeader->e_lfanew + (DWORD)DllHandle);
	// ��ȡstart�����ƫ��
	PIMAGE_SECTION_HEADER TestSection = FindSection(NtHeader, ".text");
	StartRVA = StartAddr - (DWORD)DllHandle - TestSection->VirtualAddress;
	// ��ȡDll�д�Žṹ��ĵ�ַ
	sharedata = (PSHARE_DATA)GetProcAddress(DllHandle, "share_data");
	if (sharedata == NULL)
		SetError(L"��ȡ�ṹ��sharedataʧ��");
	// ��ȡDll�д��ѹ���ļ����ݵĵ�ַ
	packdata = (PPACK_DATA)GetProcAddress(DllHandle, "pack_data");
	if (packdata == NULL)
		SetError(L"��ȡ�ṹ��packdataʧ��");
	relocdata = (PRELOC_DATA)GetProcAddress(DllHandle, "reloc_data");
	if (relocdata == NULL)
		SetError(L"��ȡ�ṹ��relocdataʧ��");
}
// �����µ�OEP
VOID CTool::SetOEP(PSHARE_DATA& sharedata, PIMAGE_NT_HEADERS FileNtHeader, DWORD FileBase, DWORD StartRVA)
{
	// ����Դ�����OEP
	// ����������ε��׵�ַ
	sharedata->OldOep = FileNtHeader->OptionalHeader.AddressOfEntryPoint;
	FileNtHeader->OptionalHeader.AddressOfEntryPoint = FindSection(FileNtHeader, ".Wang")->VirtualAddress + StartRVA;
}
// ��ʼ�����������ڻ�ȡ�����ļ���Ntͷ
VOID CTool::InitNtHeader(PIMAGE_NT_HEADERS& FileNtHeader, PIMAGE_NT_HEADERS& DllNtHeader, DWORD FileBase, HMODULE DllHandle)
{
	PIMAGE_DOS_HEADER FileDosHeader = (PIMAGE_DOS_HEADER)FileBase;
	FileNtHeader = (PIMAGE_NT_HEADERS)(FileDosHeader->e_lfanew + FileBase);
	PIMAGE_DOS_HEADER DllDosHeader = (PIMAGE_DOS_HEADER)DllHandle;
	DllNtHeader = (PIMAGE_NT_HEADERS)(DllDosHeader->e_lfanew + (DWORD)DllHandle);
}
// �޸��ض�λ��
VOID CTool::FixReloc(PIMAGE_NT_HEADERS& FileNtHeader, PIMAGE_NT_HEADERS DllNtHeader, HMODULE DllHandle, DWORD FileBase)
{
	// �����ɴ���dll���ض�λ���������ֶ��޸�
	// �޸���ĵ�ַ=���ƫ��+�ӿǳ���ļ��ػ�ַ+����.Wang��RVA
	// ���ƫ��=�ض�λ���б���ĵ�ַ-Dll�ļ��ػ�ַ-dll��.test��RVA
	PIMAGE_BASE_RELOCATION DllReloc = (PIMAGE_BASE_RELOCATION)(DllNtHeader->OptionalHeader.DataDirectory[5].VirtualAddress + (DWORD)DllHandle);
	while (DllReloc->SizeOfBlock != 0)
	{
		DWORD Count = (DllReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
		// ����ṹ��
		typedef struct TypeOffset
		{
			WORD Offset : 12;
			WORD Type : 4;
		}TypeOffset, * PTypeOffset;
		// ��ȡ��һ���ض�λ��
		PTypeOffset RelocItem = (PTypeOffset)((DWORD)DllReloc + sizeof(IMAGE_BASE_RELOCATION));
		DWORD OldProtect = 0;

		for (int i = 0; i < Count; i++)
		{
			// ����ض�λ����Ϊ3���ض�λָ���������ַ����Ҫ�������ͽ����޸���
			if ((RelocItem + i)->Type == 3)
			{
				DWORD* address = (DWORD*)((DWORD)DllHandle + (RelocItem + i)->Offset + DllReloc->VirtualAddress);
				// �������ƫ��
				DWORD RelativeOffset = *address - (DWORD)DllHandle - FindSection(DllNtHeader, ".text")->VirtualAddress;
				VirtualProtect(address, 4, PAGE_EXECUTE_READWRITE, &OldProtect);
				// �ټ�����������������ض�λ��ַ
				*address = RelativeOffset + FileNtHeader->OptionalHeader.ImageBase + FindSection(FileNtHeader, ".Wang")->VirtualAddress;
				// �ָ��ڴ�����
				VirtualProtect(address, 4, OldProtect, &OldProtect);
			}
		}
		// ��һ���ض�λ��
		DllReloc = (PIMAGE_BASE_RELOCATION)((DWORD)DllReloc + DllReloc->SizeOfBlock);
	}
	// �ر�:(& ~��־λ)    ����:(|��־λ)
	// FileNtHeader->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
}
// �����������ݵ��ӿǳ���������������
VOID CTool::CopySectionData(PIMAGE_NT_HEADERS& FileNtHeader, PIMAGE_NT_HEADERS DllNtHeader, DWORD FileBase, HMODULE DllHandle)
{
	// ��ȡ�ӿǳ����������������
	// ��ȡ�Ǵ����е�.test��
	// �޸��ڴ�����
	// ���п�������
	// ��ԭ�ڴ�����
	auto FileSection = FindSection(FileNtHeader, ".Wang");
	PVOID FileBuffer = (PVOID)(FileSection->PointerToRawData + FileBase);
	auto DllSection = FindSection(DllNtHeader, ".text");
	PVOID DllBuffer = (PVOID)(DllSection->VirtualAddress + (DWORD)DllHandle);

	DWORD OldProtect = 0;
	// VirtualProtect((LPVOID)(FileSection->VirtualAddress + FileBase), 0x1000,PAGE_EXECUTE_READWRITE, &OldProtect);
	memcpy(FileBuffer, DllBuffer, FileSection->Misc.VirtualSize);
	// VirtualProtect((LPVOID)(FileSection->VirtualAddress + FileBase), 0x1000, OldProtect, &OldProtect);
}
// ���ܴ����
VOID CTool::EnCodeText(PIMAGE_NT_HEADERS& FileNtHeader, DWORD FileBase, PSHARE_DATA& sharedata)
{
	// ��ȡ�ӿǳ���Ĵ�������
	// RVAתVA
	// �����ֽڼ���
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
// ѹ��Դ����
VOID CTool::PackFile(PIMAGE_NT_HEADERS& FileNtHeader, PIMAGE_NT_HEADERS& DllNtHeader, PPACK_DATA& packdata, DWORD& FileBase, DWORD& FileSize, HMODULE& DllHandle)
{
	packdata->IfPack = TRUE;
	int SecTextSize = FindSection(FileNtHeader, ".text")->SizeOfRawData;
	char* TextSecData = (char*)(FindSection(FileNtHeader, ".text")->PointerToRawData + FileBase);
	packdata->SizeOfRawData = SecTextSize;
	//��ѹ��������,Packed����ѹ�����ݵĿռ䣬WorkMemΪ���ѹ����Ҫʹ�õĿռ�
	// �����ڴ�ռ䣬���ڱ���ѹ���������
	char* pBuff = (char*)malloc(LZ4_compressBound(SecTextSize));
	// ��ʼѹ���ļ����ݣ���������ѹ����Ĵ�С��
	int RelcompressSize = LZ4_compress(TextSecData, pBuff, SecTextSize);
	DWORD AlignSize = GetAligMent(RelcompressSize, 0x200);

	//�¿ռ��С
	DWORD NewFileSize = FileSize - FindSection(FileNtHeader, ".text")->SizeOfRawData + AlignSize;
	//�����µĿռ��С �ļ���С - �������ļ��еĴ�С + ѹ����Ĵ�С(������)
	DWORD NewFileBase = (DWORD)malloc(NewFileSize);
	//TextSecData֮ǰ������
	DWORD PreText = FindSection(FileNtHeader, ".text")->PointerToRawData - 1;
	//����TextSecData��֮ǰ������
	memcpy((LPVOID)NewFileBase, (LPVOID)FileBase, PreText);
	//����ѹ�����ֵ�����
	memcpy((LPVOID)(NewFileBase + PreText + 1), pBuff, RelcompressSize);
	//����TextSecData�κ��������
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
	// 1. ��ȡ��Ŀ��ģ������α�   
	auto Sections = IMAGE_FIRST_SECTION(GetNtHeader(FileBase));

	// 2. ʹ���ļ�ͷ�е����������������α�   
	WORD Count = (WORD)(GetNtHeader(FileBase)->FileHeader.NumberOfSections);
	BOOL bChangeFoa = FALSE;
	for (WORD i = 0; i < Count; ++i)
	{
		if (bChangeFoa) {
			Sections[i].PointerToRawData = Sections[i].PointerToRawData - FindSection(FileNtHeader, ".text")->SizeOfRawData + AlignSize;
		}
		// 3. .text����֮ǰ�����β��ı�,����.text����֮�������
		if (!_strcmpi((char*)Sections[i].Name, ".text")) {
			bChangeFoa = TRUE;
		}
	}
	packdata->FileCompressSize = RelcompressSize;
	packdata->TextRVA = FindSection(FileNtHeader, ".text")->VirtualAddress;
	FileSize = NewFileSize;
}
// ����IAT��ȡ��ϵͳ��IAT�Ĳ���Ȩ
VOID CTool::ZeroIAT(PIMAGE_NT_HEADERS& FileNtHeader, PSHARE_DATA& sharedata)
{
	sharedata->IATRVA = FileNtHeader->OptionalHeader.DataDirectory[1].VirtualAddress;
	FileNtHeader->OptionalHeader.DataDirectory[1].VirtualAddress = 0;
	FileNtHeader->OptionalHeader.DataDirectory[12].VirtualAddress = 0;
}
// �������
VOID CTool::AddSection(LPCSTR SectionName, ULONG_PTR& FileBase, DWORD& FileSize, DWORD Size)
{
	// ��ȡDosͷ
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)FileBase;
	// ��ȡNtͷ
	PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)(FileBase + DosHeader->e_lfanew);
	// ��ȡ��������
	DWORD SectionNumber = NtHeader->FileHeader.NumberOfSections;
	// ��ȡ����
	auto FirstSection = IMAGE_FIRST_SECTION(NtHeader);
	// ��ȡ���һ������
	auto LastSection = &FirstSection[SectionNumber - 1];
	// ����������
	auto NewSection = LastSection + 1;
	//Name
	memcpy(NewSection->Name, SectionName, 7);
	//VirtualSize
	NewSection->Misc.VirtualSize = GetAligMent(Size, NtHeader->OptionalHeader.SectionAlignment);
	//VirtualAddress = ���һ�����ε� VirtualAddress +���һ�������ڴ��С
	NewSection->VirtualAddress = LastSection->VirtualAddress +
		GetAligMent(LastSection->Misc.VirtualSize, NtHeader->OptionalHeader.SectionAlignment);
	//SizeOfRawData
	NewSection->SizeOfRawData = GetAligMent(Size, NtHeader->OptionalHeader.FileAlignment);
	//PointerToRawData = ���һ�����ε� PointerToRawData + ���һ�������ļ���С
	NewSection->PointerToRawData = LastSection->PointerToRawData +
		GetAligMent(LastSection->SizeOfRawData, NtHeader->OptionalHeader.FileAlignment);
	//Characteristics
	NewSection->Characteristics = 0xE00000E0;
	// ����������һ
	NtHeader->FileHeader.NumberOfSections += 1;
	//SizeOfImage��С
	NtHeader->OptionalHeader.SizeOfImage += GetAligMent(NewSection->Misc.VirtualSize, NtHeader->OptionalHeader.SectionAlignment);
	//���·���ռ䣬����������ӵ��ѿռ���
	FileSize = NewSection->SizeOfRawData + NewSection->PointerToRawData;
	FileBase = (DWORD)realloc((VOID*)FileBase, FileSize);
	// ��ȡDosͷ
	DosHeader = (PIMAGE_DOS_HEADER)FileBase;
	// ��ȡNtͷ
	NtHeader = (PIMAGE_NT_HEADERS)(FileBase + DosHeader->e_lfanew);
	NewSection = FindSection(NtHeader, SectionName);
	memset((DWORD*)(NewSection->PointerToRawData + FileBase), 0, NewSection->SizeOfRawData);
	return;
}
// �����ض�λ��ָ������������
VOID CTool::SetReloc(PIMAGE_NT_HEADERS& FileNtHeader, PIMAGE_NT_HEADERS& DllNtHeader, RELOC_DATA& relocdata, ULONG_PTR& FileBase, DWORD& FileSize, HMODULE& DllHandle)
{
	// ��ȡ�ӿǳ�����ض�λ����Ϣ
	auto FileReloc = FileNtHeader->OptionalHeader.DataDirectory[5];
	relocdata.RelocRVA = FileReloc.VirtualAddress;
	relocdata.RelocSize = FileReloc.Size;
	relocdata.ImageBase = FileNtHeader->OptionalHeader.ImageBase;
	relocdata.OldImageBase = FileNtHeader->OptionalHeader.ImageBase;
	//Dll�ض�λ��
	auto DllBaseReloc = (PIMAGE_BASE_RELOCATION)(DllNtHeader->OptionalHeader.DataDirectory[5].VirtualAddress + (DWORD)DllHandle);
	DWORD DllRelocaSize = DllNtHeader->OptionalHeader.DataDirectory[5].Size;
	//��������
	AddSection(".NReloc", FileBase, FileSize, DllRelocaSize);
	InitNtHeader(FileNtHeader, DllNtHeader, FileBase, DllHandle);
	auto NewSecHed = FindSection(FileNtHeader, ".NReloc");
	auto OldSecHed = FindSection(DllNtHeader, ".text");
	auto PackSecHed = FindSection(FileNtHeader, ".Wang");
	auto NewRelocaSection = (PIMAGE_BASE_RELOCATION)(NewSecHed->PointerToRawData + FileBase);
	DWORD OldSectionAddr = (DWORD)(OldSecHed->VirtualAddress + (DWORD)DllHandle);

	memcpy((DWORD*)NewRelocaSection, (DWORD*)(DllBaseReloc), DllRelocaSize);
	while (NewRelocaSection->VirtualAddress) {
		//�µ��ڴ�ҳ��ʼRVA = ԭRVA - ԭ�λ�ַ +.pack�λ�ַ
		NewRelocaSection->VirtualAddress = NewRelocaSection->VirtualAddress - (OldSectionAddr - (DWORD)DllHandle) + PackSecHed->VirtualAddress;
		NewRelocaSection = (PIMAGE_BASE_RELOCATION)(NewRelocaSection->SizeOfBlock + (DWORD)NewRelocaSection);
	}
	//�滻ԭ�����ض�λ��
	FileNtHeader->OptionalHeader.DataDirectory[5].VirtualAddress = NewSecHed->VirtualAddress;
	FileNtHeader->OptionalHeader.DataDirectory[5].Size = DllRelocaSize;
}
// RVAתFOA
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

//����TLS�����TLS
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
// ����Դ����ӿǳ��� 
 VOID CTool::AddResource(LPCWSTR FileName)
{
	// ��ȡָ��ģ�������Դ
	HRSRC hRsrc = FindResource(NULL, MAKEINTRESOURCE(IDR_MYRES2), L"MYRES");
	// ��ȡ��Դ��С
	DWORD dwSize = SizeofResource(NULL, hRsrc);
	// ����Դ���ص��ڴ���
	HGLOBAL hGlobal = LoadResource(NULL, hRsrc);
	// ������Դ
	LPVOID lpVoid = LockResource(hGlobal);
	HANDLE hResource=BeginUpdateResource(FileName, FALSE);
	// ������ԴΪ�ļ�	
	UpdateResource(hResource, L"MYRES",L"6666",LANG_CHINESE, lpVoid, dwSize);
	EndUpdateResource(hResource, FALSE);
}