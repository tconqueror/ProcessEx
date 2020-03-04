
// ProcessExDlg.cpp : implementation file
//

#include "pch.h"
#include "framework.h"
#include "ProcessEx.h"
#include "ProcessExDlg.h"
#include "afxdialogex.h"
#include <TlHelp32.h>
#include <winternl.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CAboutDlg dialog used for App About

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
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


// CProcessExDlg dialog



CProcessExDlg::CProcessExDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_PROCESSEX_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CProcessExDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, result);
}

BEGIN_MESSAGE_MAP(CProcessExDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CProcessExDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDOK, &CProcessExDlg::OnBnClickedOK)
END_MESSAGE_MAP()


// CProcessExDlg message handlers

BOOL CProcessExDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
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

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	result.InsertColumn(0, L"FullPath", LVCFMT_LEFT, 220);
	result.InsertColumn(0, L"CommandLine", LVCFMT_LEFT, 220);
	result.InsertColumn(0, L"ProcessName", LVCFMT_LEFT, 100);
	result.InsertColumn(0, L"PID", LVCFMT_LEFT, 40);
	
	result.SetExtendedStyle(result.GetExtendedStyle() | LVS_EX_FULLROWSELECT);
	//SET SYSTEM PRIVILEGE
	HANDLE token;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token))
	{
		AfxMessageBox(L"Failed when get token");
		return TRUE;
	}
	TOKEN_PRIVILEGES tkp;
	tkp.PrivilegeCount = 1;
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(token, false, &tkp, sizeof(tkp), NULL, NULL))
	{
		AfxMessageBox(L"Fail when adjust token");
		CloseHandle(token);
		return TRUE;
	}
	CloseHandle(token);
	hntdll = LoadLibrary(L"ntdll.dll");
	if (hntdll == NULL)
	{
		AfxMessageBox(L"Fail when load dll");
		return false;
	}
	gNtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hntdll, "NtQueryInformationProcess");
	if (gNtQueryInformationProcess == NULL)
	{
		FreeLibrary(hntdll);
		AfxMessageBox(L"Fail when load NtQuery");
		return false;
	}
	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CProcessExDlg::OnSysCommand(UINT nID, LPARAM lParam)
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

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CProcessExDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CProcessExDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



CString CProcessExDlg::intToCString(DWORD64 n)
{
	CString temp;
	temp.Format(_T("%lld"), n);
	return temp;
}

void CProcessExDlg::OnBnClickedButton1()
{
	result.DeleteAllItems();
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		AfxMessageBox(L"Error when create tool help 32 snapshot!");
		return;
	}
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcessSnap, &pe32))
	{
		AfxMessageBox(L"Error when call process32first");
		CloseHandle(hProcessSnap);
		return;
	}
	int count = 0;
	do
	{
		int n = result.InsertItem(count++, intToCString(pe32.th32ProcessID));
		result.SetItemText(n, 1, (pe32.szExeFile));
		HANDLE hModule = NULL;
		hModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, pe32.th32ProcessID);
		if (hModule == INVALID_HANDLE_VALUE)
			continue;
		MODULEENTRY32 me32;
		me32.dwSize = sizeof(MODULEENTRY32);
		if (!Module32First(hModule, &me32))
		{
			CloseHandle(hModule);
			continue;
		}
		result.SetItemText(n, 3, me32.szExePath);
		CloseHandle(hModule);
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
		if (hProcess == INVALID_HANDLE_VALUE)
		{
			continue;
		}
		HANDLE heap = GetProcessHeap();
		DWORD dwSize = sizeof(PROCESS_BASIC_INFORMATION);
		PROCESS_BASIC_INFORMATION* pbi = (PROCESS_BASIC_INFORMATION*)calloc(1, dwSize);
		if (!pbi)
		{
			CloseHandle(hProcess);
			continue;
		}
		NTSTATUS dwStatus = gNtQueryInformationProcess(hProcess, ProcessBasicInformation, pbi, dwSize, NULL);
		if (dwStatus < 0)
		{
			free(pbi);
			CloseHandle(hProcess);
			continue;
		}
		if (pbi->PebBaseAddress)
		{
			PEB peb;
			if (ReadProcessMemory(hProcess, pbi->PebBaseAddress, &peb, sizeof(peb), NULL) == 0)
			{
				free(pbi);
				CloseHandle(hProcess);
				continue;
			}
			UNICODE_STRING cml;
			if (ReadProcessMemory(hProcess, &peb.ProcessParameters->CommandLine, &cml, sizeof(cml), NULL) == 0)
			{
				free(pbi);
				CloseHandle(hProcess);
				continue;
			}
			WCHAR x[1024] = { 0 };
			if (ReadProcessMemory(hProcess, cml.Buffer, x, (cml.Length+2 > 1024 ? 1024: cml.Length+2), NULL) == 0)
			{
				free(pbi);
				CloseHandle(hProcess);
				continue;
			}
			result.SetItemText(n, 2, x);
		}
		CloseHandle(hProcess);
		free(pbi);
	} while (Process32Next(hProcessSnap, &pe32));
	CloseHandle(hProcessSnap);
	//FreeLibrary(hntdll);
	//gNtQueryInformationProcess = NULL;
}

void CProcessExDlg::OnBnClickedOK()
{
	OnBnClickedButton1();
}
