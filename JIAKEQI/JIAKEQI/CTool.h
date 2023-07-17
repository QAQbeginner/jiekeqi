#pragma once
// 定义结构体
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
// 定义结构体
typedef struct _PACK_DATA
{
	// 加壳程序代码段大小
	DWORD SizeOfRawData;
	// 加壳程序压缩后的大小
	DWORD FileCompressSize;
	// 代码段偏移
	DWORD TextRVA;
	// 判断是否进行压缩
	BOOL IfPack = FALSE;
}PACK_DATA, * PPACK_DATA;
// 定义结构体用于保存重定位数据
typedef struct _RELOC_DATA
{
	// RVA；重定位表的大小；加载基址
	DWORD RelocRVA;
	DWORD RelocSize;
	DWORD ImageBase;
	DWORD OldImageBase;
}RELOC_DATA, * PRELOC_DATA;
class CTool
{
private:
	// 用于寻找区段
	static PIMAGE_SECTION_HEADER FindSection(PIMAGE_NT_HEADERS NtHeader, LPCSTR SectionName);
	// 获取DOS头
	static PIMAGE_NT_HEADERS GetNtHeader(ULONG_PTR FileBase);
	// 用于计算对齐后的文件大小
	static DWORD GetAligMent(DWORD Size, DWORD AligMent);
	// 用于报错
	static VOID SetError(LPCWSTR ErrorInfo);
	// RVA转FOA
	static DWORD RvaToOffset(DWORD lpImage, DWORD dwRva);
public:
	// 申请空间读取文件内容到内存
	static BOOL OpenPE(LPCWSTR FileName, ULONG_PTR& FileBase);
	// 加载生成的 壳代码dll
	static VOID LoadShellCode(HMODULE& DllHandle, LPCWSTR FileName, DWORD& StartRVA, PSHARE_DATA& sharedata, PPACK_DATA& packdata, PRELOC_DATA& relocdata);
	// 获取区段数量，并在区段的最后添加自己的区段[获取指定模块的.test段，复制到新增添的区段]
	static BOOL CopySection(LPCSTR SectionName, ULONG_PTR& FileBase, DWORD& FileSize, PIMAGE_NT_HEADERS DllNtHeader);
	// 将内存写入文件
	static BOOL ChangeFile(LPCWSTR FileName, ULONG_PTR& FileBase, DWORD FileSize);
	// 设置新的OEP
	static VOID SetOEP(PSHARE_DATA& sharedata, PIMAGE_NT_HEADERS FileNtHeader, DWORD FileBase, DWORD StartRVA);
	// 初始化函数，用于获取两个文件的Nt头
	static VOID InitNtHeader(PIMAGE_NT_HEADERS& FileNtHeader, PIMAGE_NT_HEADERS& DllNtHeader, DWORD FileBase, HMODULE DllHandle);
	// 修复重定位表
	static VOID FixReloc(PIMAGE_NT_HEADERS& FileNtHeader, PIMAGE_NT_HEADERS DllNtHeader, HMODULE DllHandle, DWORD FileBase);
	// 拷贝区段内容到加壳程序中新增的区段
	static VOID CopySectionData(PIMAGE_NT_HEADERS& FileNtHeader, PIMAGE_NT_HEADERS DllNtHeader, DWORD FileBase, HMODULE DllHandle);
	// 加密代码段
	static VOID EnCodeText(PIMAGE_NT_HEADERS& FileNtHeader, DWORD FileBase, PSHARE_DATA& sharedata);
	// 压缩源程序
	static VOID PackFile(PIMAGE_NT_HEADERS& FileNtHeader, PIMAGE_NT_HEADERS& DllNtHeader, PPACK_DATA& packdata, DWORD& FileBase, DWORD& FileSize, HMODULE& DllHandle);
	// 清零IAT，取消系统对IAT的操作权
	static VOID ZeroIAT(PIMAGE_NT_HEADERS& FileNtHeader, PSHARE_DATA& sharedata);
	// 添加区段
	static VOID AddSection(LPCSTR SectionName, ULONG_PTR& FileBase, DWORD& FileSize, DWORD Size);
	// 设置重定位表指向新增的区段了
	static VOID SetReloc(PIMAGE_NT_HEADERS& FileNtHeader, PIMAGE_NT_HEADERS& DllNtHeader, RELOC_DATA& relocdata, ULONG_PTR& FileBase, DWORD& FileSize, HMODULE& DllHandle);
	// 将TLS清零
	static VOID SetTls(PIMAGE_NT_HEADERS& FileNtHeader, ULONG_PTR& FileBase, PSHARE_DATA& sharedata);
	// 将资源加入加壳程序 
	static VOID AddResource(LPCWSTR FileName);
};

