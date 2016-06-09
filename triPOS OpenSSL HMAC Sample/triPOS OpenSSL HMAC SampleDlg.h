
// triPOS OpenSSL HMAC SampleDlg.h : header file
//

#pragma once
#include "afxwin.h"

#include <string>

// CtriPOSOpenSSLHMACSampleDlg dialog
class CtriPOSOpenSSLHMACSampleDlg : public CDialogEx
{
// Construction
public:
	CtriPOSOpenSSLHMACSampleDlg(CWnd* pParent = NULL);	// standard constructor

// Dialog Data
	enum { IDD = IDD_TRIPOSOPENSSLHMACSAMPLE_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()

private:
    std::string CtriPOSOpenSSLHMACSampleDlg::HashCanonicalRequest(std::wstring method, std::wstring uri, std::wstring headers, std::wstring body, std::wstring algorithm);
    std::string CtriPOSOpenSSLHMACSampleDlg::CreateSigningKey(std::wstring requestDate, std::wstring nonce, std::wstring developerSecret, std::wstring algorithm);
    std::string CtriPOSOpenSSLHMACSampleDlg::CreateRequestSignature(std::wstring requestDate, std::wstring developerKey, std::string hashedCanonicalRequest, std::string signingKey, std::wstring algorithm);
    std::string CtriPOSOpenSSLHMACSampleDlg::CreateTpAuthorizationHeader(std::wstring version, std::wstring developerKey, std::wstring headers, std::wstring nonce, std::wstring requestDate, std::string requestSignature, std::wstring algorithm);

	std::string CtriPOSOpenSSLHMACSampleDlg::GenerateTPAuth();
    void CtriPOSOpenSSLHMACSampleDlg::OutputClear();
    void CtriPOSOpenSSLHMACSampleDlg::Output(const void *value, int length, const char *tag = NULL);
    void CtriPOSOpenSSLHMACSampleDlg::Output(const char *value, const char *tag = NULL);
    void CtriPOSOpenSSLHMACSampleDlg::Output(std::string value, const char *tag = NULL);
    void CtriPOSOpenSSLHMACSampleDlg::Output(int value, const char *tag = NULL);

    std::string CtriPOSOpenSSLHMACSampleDlg::ToHexString(const void *value, int length);

    std::string CtriPOSOpenSSLHMACSampleDlg::FixNewlinesForOutput(std::string value);

    void CtriPOSOpenSSLHMACSampleDlg::ParseUri(std::wstring uri, std::string &scheme, std::string &host, std::string &port, std::string &path, std::string &query);
    std::string CtriPOSOpenSSLHMACSampleDlg::SortQuery(std::string query);

    std::string CtriPOSOpenSSLHMACSampleDlg::HashValue(const void *value, int length, std::wstring algorithm);
    std::string CtriPOSOpenSSLHMACSampleDlg::KeyedHashValue(const void *value, int length, std::wstring algorithm, std::string key);

    std::string CtriPOSOpenSSLHMACSampleDlg::GetCanonicalSignedHeaders(std::wstring headers);
    std::string CtriPOSOpenSSLHMACSampleDlg::GetCanonicalHeaders(std::wstring headers);

    std::string CtriPOSOpenSSLHMACSampleDlg::ToMultiByte(LPCTSTR wideChar);

    std::string CtriPOSOpenSSLHMACSampleDlg::Trim(std::string string, char trimChar = ' ');
	void CtriPOSOpenSSLHMACSampleDlg::CollectInput();

	std::wstring method;
	std::wstring algorithm;
	std::wstring version;
	std::wstring requestDate;
	std::wstring uri;
	std::wstring nonce;
	std::wstring developerKey;
	std::wstring developerSecret;
	std::wstring headers;
	std::wstring body;

public:
    CComboBox m_comboBoxMethod;
    CComboBox m_comboBoxAlgorithm;
    CEdit m_editVersion;
    CEdit m_editRequestDate;
    CEdit m_editUri;
    CEdit m_editNonce;
    CEdit m_editDeveloperKey;
    CEdit m_editDeveloperSecret;
    CEdit m_editHeaders;
    CEdit m_editBody;
    CEdit m_editOutput;
	CEdit m_editOutput2;
    afx_msg void OnBnClickedButtonGo();
	afx_msg void OnBnClickedButtonGo3();
};
