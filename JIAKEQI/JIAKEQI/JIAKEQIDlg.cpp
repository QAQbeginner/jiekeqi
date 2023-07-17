
// JIAKEQIDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "JIAKEQI.h"
#include "JIAKEQIDlg.h"
#include "afxdialogex.h"
#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CJIAKEQIDlg 对话框



CJIAKEQIDlg::CJIAKEQIDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_JIAKEQI_DIALOG, pParent)
	, PathString(_T(""))
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CJIAKEQIDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT1, PathString);
	DDX_Control(pDX, IDC_RADIO1, PathButton);
}

BEGIN_MESSAGE_MAP(CJIAKEQIDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CJIAKEQIDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_RADIO1, &CJIAKEQIDlg::OnBnClickedRadio1)
END_MESSAGE_MAP()


// CJIAKEQIDlg 消息处理程序

BOOL CJIAKEQIDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CJIAKEQIDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CJIAKEQIDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CJIAKEQIDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}
// 进行加壳
void CJIAKEQIDlg::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码
	// 添加资源
	CTool::AddResource((LPCWSTR)PathString);
	// 打开文件并读取文件到内存
	CTool::OpenPE((LPCWSTR)PathString, FileBase);
	// 加载壳代码模块
	CTool::LoadShellCode(DllHandle, L"ShellCode.dll", StartRVA, ShareData, PackData, RelocData);
	// 初始化，获取Nt头
	CTool::InitNtHeader(FileNtHeader, DllNtHeader, FileBase, DllHandle);
	// 增加区段
	CTool::CopySection(".Wang", FileBase, FileSize, DllNtHeader);
	// 初始化，获取Nt头
	CTool::InitNtHeader(FileNtHeader, DllNtHeader, FileBase, DllHandle);
	// 设置OEP
	CTool::SetOEP(ShareData, FileNtHeader, FileBase, StartRVA);
	// 清零IAT
	CTool::ZeroIAT(FileNtHeader, ShareData);
	// 清零TLS
	CTool::SetTls(FileNtHeader, FileBase, ShareData);
	// 修复重定位表
	CTool::FixReloc(FileNtHeader, DllNtHeader, DllHandle, FileBase);
	// 添加区段，将重定位指向新添加区段
	CTool::SetReloc(FileNtHeader, DllNtHeader, *RelocData, FileBase, FileSize, DllHandle);
	// 加密代码段
	CTool::EnCodeText(FileNtHeader, FileBase, ShareData);
	int ret = MessageBox(L"提示", L"是否进行压缩", MB_OKCANCEL);
	if (ret == IDOK)
		CTool::PackFile(FileNtHeader, DllNtHeader, PackData, FileBase, FileSize, DllHandle);
	// 写入数据
	CTool::CopySectionData(FileNtHeader, DllNtHeader, FileBase, DllHandle);
	// 写入文件
	CTool::ChangeFile((LPCWSTR)PathString, FileBase, FileSize);
}
/*
	获取指定目录下路径
*/
CString GetPathFrom()
{
	TCHAR szBuffer[MAX_PATH] = { 0 };
	BROWSEINFO bi;
	ZeroMemory(&bi, sizeof(BROWSEINFO));
	bi.hwndOwner = NULL;
	bi.pszDisplayName = szBuffer;
	bi.lpszTitle = _T("从下面选文件夹目录:");
	bi.ulFlags = BIF_BROWSEINCLUDEFILES;// BIF_RETURNFSANCESTORS
	LPITEMIDLIST idl = SHBrowseForFolder(&bi);
	if (NULL == idl)
	{
		return CString("");
	}
	SHGetPathFromIDList(idl, szBuffer);
	return szBuffer;
}
// 获取文件路径
void CJIAKEQIDlg::OnBnClickedRadio1()
{
	// TODO: 在此添加控件通知处理程序代码
	PathString = GetPathFrom();
	if (PathString == TEXT(""))
	{
		PathButton.SetCheck(FALSE);
		return;
	}
	UpdateData(FALSE);
}
