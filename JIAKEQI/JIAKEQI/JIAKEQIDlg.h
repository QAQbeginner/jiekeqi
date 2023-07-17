
// JIAKEQIDlg.h: 头文件
//

#pragma once
#include "CTool.h"

// CJIAKEQIDlg 对话框
class CJIAKEQIDlg : public CDialogEx
{
// 构造
public:
	CJIAKEQIDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_JIAKEQI_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButton1();
	CString PathString;
public:
	// 文件加载基址
	ULONG_PTR FileBase = 0;
	// 文件大小
	DWORD FileSize = 0;
	// 文件Nt头
	PIMAGE_NT_HEADERS FileNtHeader = 0;
	// 壳代码dll的Nt头
	PIMAGE_NT_HEADERS DllNtHeader = 0;
	// 壳代码首地址
	HMODULE DllHandle = 0;
	// 定义接受数据的结构体
	PSHARE_DATA ShareData;
	// 定义接受压缩数据的结构体
	PPACK_DATA PackData;
	// 定义接收重定位数据的结构体
	PRELOC_DATA RelocData;
	// 定义壳代码中运行函数的相对偏移
	DWORD StartRVA = 0;
	afx_msg void OnBnClickedRadio1();
	CButton PathButton;
};
