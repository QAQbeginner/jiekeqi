#pragma once
// ����ṹ��
typedef struct _SHARE_DATA
{
	ULONG_PTR OldOep;
	ULONG_PTR XorStart;
	SIZE_T XorAddr;
	BYTE XorKey;
	DWORD IATRVA;
	DWORD TlsVirtualAddress;
	DWORD TlsCallBackTableVa;
} SHARE_DATA, * PSHARE_DATA;
// ����ṹ��
typedef struct _PACK_DATA
{
	// �ӿǳ������δ�С
	DWORD SizeOfRawData;
	// �ӿǳ���ѹ����Ĵ�С
	DWORD FileCompressSize;
	// �����ƫ��
	DWORD TextRVA;
	// �ж��Ƿ����ѹ��
	BOOL IfPack = FALSE;
}PACK_DATA, * PPACK_DATA;
// ����ṹ�����ڱ����ض�λ����
typedef struct _RELOC_DATA
{
	// RVA���ض�λ��Ĵ�С�����ػ�ַ
	DWORD RelocRVA;
	DWORD RelocSize;
	DWORD ImageBase;
	DWORD OldImageBase;
}RELOC_DATA, * PRELOC_DATA;
class CTool
{
private:
	// ����Ѱ������
	static PIMAGE_SECTION_HEADER FindSection(PIMAGE_NT_HEADERS NtHeader, LPCSTR SectionName);
	// ��ȡDOSͷ
	static PIMAGE_NT_HEADERS GetNtHeader(ULONG_PTR FileBase);
	// ���ڼ���������ļ���С
	static DWORD GetAligMent(DWORD Size, DWORD AligMent);
	// ���ڱ���
	static VOID SetError(LPCWSTR ErrorInfo);
	// RVAתFOA
	static DWORD RvaToOffset(DWORD lpImage, DWORD dwRva);
public:
	// ����ռ��ȡ�ļ����ݵ��ڴ�
	static BOOL OpenPE(LPCWSTR FileName, ULONG_PTR& FileBase);
	// �������ɵ� �Ǵ���dll
	static VOID LoadShellCode(HMODULE& DllHandle, LPCWSTR FileName, DWORD& StartRVA, PSHARE_DATA& sharedata, PPACK_DATA& packdata, PRELOC_DATA& relocdata);
	// ��ȡ�����������������ε��������Լ�������[��ȡָ��ģ���.test�Σ����Ƶ������������]
	static BOOL CopySection(LPCSTR SectionName, ULONG_PTR& FileBase, DWORD& FileSize, PIMAGE_NT_HEADERS DllNtHeader);
	// ���ڴ�д���ļ�
	static BOOL ChangeFile(LPCWSTR FileName, ULONG_PTR& FileBase, DWORD FileSize);
	// �����µ�OEP
	static VOID SetOEP(PSHARE_DATA& sharedata, PIMAGE_NT_HEADERS FileNtHeader, DWORD FileBase, DWORD StartRVA);
	// ��ʼ�����������ڻ�ȡ�����ļ���Ntͷ
	static VOID InitNtHeader(PIMAGE_NT_HEADERS& FileNtHeader, PIMAGE_NT_HEADERS& DllNtHeader, DWORD FileBase, HMODULE DllHandle);
	// �޸��ض�λ��
	static VOID FixReloc(PIMAGE_NT_HEADERS& FileNtHeader, PIMAGE_NT_HEADERS DllNtHeader, HMODULE DllHandle, DWORD FileBase);
	// �����������ݵ��ӿǳ���������������
	static VOID CopySectionData(PIMAGE_NT_HEADERS& FileNtHeader, PIMAGE_NT_HEADERS DllNtHeader, DWORD FileBase, HMODULE DllHandle);
	// ���ܴ����
	static VOID EnCodeText(PIMAGE_NT_HEADERS& FileNtHeader, DWORD FileBase, PSHARE_DATA& sharedata);
	// ѹ��Դ����
	static VOID PackFile(PIMAGE_NT_HEADERS& FileNtHeader, PIMAGE_NT_HEADERS& DllNtHeader, PPACK_DATA& packdata, DWORD& FileBase, DWORD& FileSize, HMODULE& DllHandle);
	// ����IAT��ȡ��ϵͳ��IAT�Ĳ���Ȩ
	static VOID ZeroIAT(PIMAGE_NT_HEADERS& FileNtHeader, PSHARE_DATA& sharedata);
	// �������
	static VOID AddSection(LPCSTR SectionName, ULONG_PTR& FileBase, DWORD& FileSize, DWORD Size);
	// �����ض�λ��ָ��������������
	static VOID SetReloc(PIMAGE_NT_HEADERS& FileNtHeader, PIMAGE_NT_HEADERS& DllNtHeader, RELOC_DATA& relocdata, ULONG_PTR& FileBase, DWORD& FileSize, HMODULE& DllHandle);
	// ��TLS����
	static VOID SetTls(PIMAGE_NT_HEADERS& FileNtHeader, ULONG_PTR& FileBase, PSHARE_DATA& sharedata);
	// ����Դ����ӿǳ��� 
	static VOID AddResource(LPCWSTR FileName);
};

