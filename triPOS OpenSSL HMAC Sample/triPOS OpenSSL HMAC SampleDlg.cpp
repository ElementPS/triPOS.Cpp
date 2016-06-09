
// triPOS OpenSSL HMAC SampleDlg.cpp : implementation file
//

#include "stdafx.h"
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "triPOS OpenSSL HMAC Sample.h"
#include "triPOS OpenSSL HMAC SampleDlg.h"
#include "afxdialogex.h"

#include <algorithm>
#include <list>
#include <locale>
#include <map>
#include <sstream>
#include <utility>
#include <iostream>
#include <string>

#pragma comment (lib, "wsock32.lib")

#include <stdlib.h>
#include <winsock.h>

#include "openssl/hmac.h"
#include "openssl/sha.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

using namespace std;

#define BUFFERSIZE 1024


LPCTSTR methods[] =
{
    L"POST",
    L"GET",
    L"PUT",
    L"DELETE",
    NULL
};

LPCTSTR algorithms[] =
{
    L"TP-HMAC-SHA1",
    NULL
};

LPCTSTR defaultHeaders = L"Content-Type: application/json\r\nAccept: application/json\r\ntp-application-id: 1234\r\ntp-application-name: CPlusPlus\r\ntp-application-version: 1.0.0\r\ntp-return-logs: false";
LPCTSTR defaultData = L"{\"address\": {\"BillingAddress1\": \"123 Sample Stree\",\"BillingAddress2\" : \"Suite 101\",\"BillingCity\" : \"Chandler\", \"BillingPostalCode\" : \"85224\", \"BillingState\" : \"AZ\"}, \"cashbackAmount\": 0, \"confenienceFeeAmount\" : 0, \"emvFallbackReason\" : \"None\", \"tipAmount\" : 0, \"clerkNumber\" : \"Clerk101\", \"configuration\" : { \"allowPartialApprovals\": false, \"checkForDuplicateTransactions\" : true, \"currencyCode\" : \"Usd\", \"marketCode\" : \"Retail\"},\"laneId\": 9999, \"referenceNumber\" : \"Ref000001\", \"shiftId\" : \"ShiftA\", \"ticketNumber\" : \"T0000001\"}";

CtriPOSOpenSSLHMACSampleDlg::CtriPOSOpenSSLHMACSampleDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CtriPOSOpenSSLHMACSampleDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CtriPOSOpenSSLHMACSampleDlg::DoDataExchange(CDataExchange* pDX)
{
    CDialogEx::DoDataExchange(pDX);
    DDX_Control(pDX, IDC_COMBO_METHOD, m_comboBoxMethod);
    DDX_Control(pDX, IDC_COMBO_ALGORITHM, m_comboBoxAlgorithm);
    DDX_Control(pDX, IDC_EDIT_VERSION, m_editVersion);
    DDX_Control(pDX, IDC_EDIT_REQUESTDATE, m_editRequestDate);
    DDX_Control(pDX, IDC_EDIT_URI, m_editUri);
    DDX_Control(pDX, IDC_EDIT_NONCE, m_editNonce);
    DDX_Control(pDX, IDC_EDIT_DEVELOPERKEY, m_editDeveloperKey);
    DDX_Control(pDX, IDC_EDIT_DEVELOPERSECRET, m_editDeveloperSecret);
    DDX_Control(pDX, IDC_EDIT_HEADERS, m_editHeaders);
    DDX_Control(pDX, IDC_EDIT_BODY, m_editBody);
    DDX_Control(pDX, IDC_EDIT_OUTPUT, m_editOutput);
	DDX_Control(pDX, IDC_EDIT_OUTPUT2, m_editOutput2);
}

BEGIN_MESSAGE_MAP(CtriPOSOpenSSLHMACSampleDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
    ON_BN_CLICKED(IDC_BUTTON_GO, &CtriPOSOpenSSLHMACSampleDlg::OnBnClickedButtonGo)
	ON_BN_CLICKED(IDC_BUTTON_GO3, &CtriPOSOpenSSLHMACSampleDlg::OnBnClickedButtonGo3)
END_MESSAGE_MAP()

BOOL CtriPOSOpenSSLHMACSampleDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// TODO: Add extra initialization here
    for (int methodIndex = 0; methods[methodIndex] != NULL; methodIndex++)
    {
        m_comboBoxMethod.AddString(methods[methodIndex]);
    }

    m_comboBoxMethod.SetCurSel(0);

    for (int algorithmIndex = 0; algorithms[algorithmIndex] != NULL; algorithmIndex++)
    {
        m_comboBoxAlgorithm.AddString(algorithms[algorithmIndex]);
    }

    m_comboBoxAlgorithm.SetCurSel(0);

    m_editVersion.SetWindowTextW(L"1.0");

    time_t now;

    time(&now);

    tm *gmtNow = gmtime(&now);

    WCHAR requestDate[32];

    wcsftime(requestDate, 32, L"%Y-%m-%dT%H:%M:%SZ", gmtNow);

    m_editRequestDate.SetWindowTextW(requestDate);

    m_editUri.SetWindowTextW(L"http://localhost:8080/api/v1/sale");

    GUID guid;

    CoCreateGuid(&guid);

    LPWSTR guidString;

    UuidToStringW(&guid, (RPC_WSTR *)&guidString);

    m_editNonce.SetWindowTextW(guidString);

    m_editHeaders.SetWindowTextW(defaultHeaders);



#if 1

    m_editUri.SetWindowTextW(L"http://localhost:8080/api/v1/sale");

    m_editNonce.SetWindowTextW(L"b61a73b9-076e-44c8-b963-0088260792f9");

    m_editDeveloperSecret.SetWindowTextW(L"");

    m_editDeveloperKey.SetWindowTextW(L"");

	m_editBody.SetWindowTextW(defaultData);

#else
    m_comboBoxMethod.SetCurSel(1);

    m_editRequestDate.SetWindowTextW(L"2015-09-28T14:24:59.906Z");

    m_editUri.SetWindowTextW(L"http://localhost:8080/api/v1/pinpad/card/nonfinancial/507");

    m_editNonce.SetWindowTextW(L"fa2ae6c1-e76f-49c3-a7bf-03805b0dc254");

    m_editDeveloperSecret.SetWindowTextW(L"");

    m_editDeveloperKey.SetWindowTextW(L"");

    m_editHeaders.SetWindowTextW(L"");
#endif


    return TRUE;  // return TRUE  unless you set the focus to a control
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CtriPOSOpenSSLHMACSampleDlg::OnPaint()
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
HCURSOR CtriPOSOpenSSLHMACSampleDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CtriPOSOpenSSLHMACSampleDlg::CollectInput()
{
	WCHAR *buffer;

	buffer = (WCHAR *)calloc(1024 + 1, sizeof(WCHAR));

	if (buffer == NULL)
	{
		Output("ERROR ALLOCATING BUFFER");

		return;
	}

	m_comboBoxMethod.GetLBText(m_comboBoxMethod.GetCurSel(), buffer);
	method = buffer;
	m_comboBoxAlgorithm.GetLBText(m_comboBoxAlgorithm.GetCurSel(), (LPTSTR)buffer);
	algorithm = buffer;
	m_editVersion.GetWindowTextW(buffer, 1024);
	version = buffer;
	m_editRequestDate.GetWindowTextW(buffer, 1024);
	requestDate = buffer;
	m_editUri.GetWindowTextW(buffer, 1024);
	uri = buffer;
	m_editNonce.GetWindowTextW(buffer, 1024);
	nonce = buffer;
	m_editDeveloperKey.GetWindowTextW(buffer, 1024);
	developerKey = buffer;
	m_editDeveloperSecret.GetWindowTextW(buffer, 1024);
	developerSecret = buffer;
	free(buffer);

	int length = m_editHeaders.GetWindowTextLengthW() + 1;
	buffer = (WCHAR *)calloc(length, sizeof(WCHAR));

	if (buffer == NULL)
	{
		Output("ERROR ALLOCATING HEADERS BUFFER");
	}

	m_editHeaders.GetWindowTextW(buffer, length);
	headers = buffer;
	free(buffer);

	length = m_editBody.GetWindowTextLengthW() + 1;
	buffer = (WCHAR *)calloc(length, sizeof(WCHAR));

	if (buffer == NULL)
	{
		Output("ERROR ALLOCATING BODY BUFFER");
	}

	m_editBody.GetWindowTextW(buffer, length);
	body = buffer;
	free(buffer);
}

std::string CtriPOSOpenSSLHMACSampleDlg::GenerateTPAuth()
{
	OutputClear();

	CollectInput();

	std::string hashedCanonicalRequest = HashCanonicalRequest(method, uri, headers, body, algorithm);

	std::string signingKey = CreateSigningKey(requestDate, nonce, developerSecret, algorithm);

	std::string requestSignature = CreateRequestSignature(requestDate, developerKey, hashedCanonicalRequest, signingKey, algorithm);

	return CreateTpAuthorizationHeader(version, developerKey, headers, nonce, requestDate, requestSignature, algorithm);
}

void CtriPOSOpenSSLHMACSampleDlg::OnBnClickedButtonGo()
{
	std::string tpAuthorization = GenerateTPAuth();
}

std::string CtriPOSOpenSSLHMACSampleDlg::HashCanonicalRequest(std::wstring method, std::wstring uri, std::wstring headers, std::wstring body, std::wstring algorithm)
{
    std::string canonicalRequest(ToMultiByte(method.c_str()));

    canonicalRequest += "\n";

    std::string scheme;

    std::string host;

    std::string port;

    std::string path;

    std::string query;

    ParseUri(uri, scheme, host, port, path, query);

    canonicalRequest += path;

    canonicalRequest += "\n";

    canonicalRequest += SortQuery(query);

    canonicalRequest += "\n";

    canonicalRequest += GetCanonicalHeaders(headers);

    canonicalRequest += "\n";

    canonicalRequest += GetCanonicalSignedHeaders(headers);

    canonicalRequest += "\n";

    if (!body.empty())
    {
        std::string bodyMultiByte(ToMultiByte(body.c_str()));

        Output(bodyMultiByte.length(), "body length");

        std::string bodyHash = HashValue(bodyMultiByte.c_str(), bodyMultiByte.length(), algorithm);

        Output(bodyHash, "bodyHash");

        canonicalRequest += bodyHash;
    }

    Output("canonicalRequest:");

    Output(FixNewlinesForOutput(canonicalRequest));

    Output(canonicalRequest.length(), "canonicalRequest length");

    std::string hashedCanonicalRequest = HashValue(canonicalRequest.c_str(), canonicalRequest.length(), algorithm);

    Output(hashedCanonicalRequest, "hashedCanonicalRequest");

    return hashedCanonicalRequest;
}

std::string CtriPOSOpenSSLHMACSampleDlg::CreateSigningKey(std::wstring requestDate, std::wstring nonce, std::wstring developerSecret, std::wstring algorithm)
{
    std::string data(ToMultiByte((nonce + developerSecret).c_str()));

    unsigned char keySignature[HMAC_MAX_MD_CBLOCK];

    unsigned int keySignatureLength;

    HMAC(EVP_sha1(), ToMultiByte(requestDate.c_str()).c_str(), requestDate.length(), (unsigned char *)data.c_str(), data.length(), keySignature, &keySignatureLength);

    std::string keySignatureString = ToHexString(keySignature, keySignatureLength);

    Output(keySignatureString, "keySignature");

    return keySignatureString;
}

std::string CtriPOSOpenSSLHMACSampleDlg::CreateRequestSignature(std::wstring requestDate, std::wstring developerKey, std::string hashedCanonicalRequest, std::string signingKey, std::wstring algorithm)
{
    std::string stringToSign(ToMultiByte(algorithm.c_str()));

    stringToSign += "\n";

    stringToSign += ToMultiByte(requestDate.c_str());

    stringToSign += "\n";

    stringToSign += ToMultiByte(developerKey.c_str());

    stringToSign += "\n";

    stringToSign += hashedCanonicalRequest;

    Output("stringToSign:");

    Output(FixNewlinesForOutput(stringToSign));

    Output(stringToSign.length(), "stringToSign length");

    unsigned char requestSignature[HMAC_MAX_MD_CBLOCK];

    unsigned int requestSignatureLength;

    HMAC(EVP_sha1(), signingKey.c_str(), signingKey.length(), (const unsigned char*)stringToSign.c_str(), stringToSign.length(), requestSignature, &requestSignatureLength);

    std::string requestSignatureString = ToHexString(requestSignature, requestSignatureLength);

    Output(requestSignatureString, "requestSignature");

    return requestSignatureString;
}

std::string CtriPOSOpenSSLHMACSampleDlg::CreateTpAuthorizationHeader(std::wstring version, std::wstring developerKey, std::wstring headers, std::wstring nonce, std::wstring requestDate, std::string requestSignature, std::wstring algorithm)
{
    std::string tpAuthorizationHeader;

    tpAuthorizationHeader = "Version=";

    tpAuthorizationHeader += ToMultiByte(version.c_str());

    tpAuthorizationHeader += ", ";

    tpAuthorizationHeader += "Algorithm=";

    tpAuthorizationHeader += ToMultiByte(algorithm.c_str());

    tpAuthorizationHeader += ", ";

    tpAuthorizationHeader += "Credential=";

    tpAuthorizationHeader += ToMultiByte(developerKey.c_str());

    tpAuthorizationHeader += ", ";

    tpAuthorizationHeader += "SignedHeaders=";

    tpAuthorizationHeader += GetCanonicalSignedHeaders(headers);

    tpAuthorizationHeader += ", ";

    tpAuthorizationHeader += "Nonce=";

    tpAuthorizationHeader += ToMultiByte(nonce.c_str());

    tpAuthorizationHeader += ", ";

    tpAuthorizationHeader += "RequestDate=";

    tpAuthorizationHeader += ToMultiByte(requestDate.c_str());

    tpAuthorizationHeader += ", ";

    tpAuthorizationHeader += "Signature=";

    tpAuthorizationHeader += requestSignature;

    Output(tpAuthorizationHeader, "tp-authorization");

    return tpAuthorizationHeader;
}

void CtriPOSOpenSSLHMACSampleDlg::OutputClear()
{
    m_editOutput.SetWindowTextW(L"");
	m_editOutput2.SetWindowTextW(L"");
}

void CtriPOSOpenSSLHMACSampleDlg::Output(const void *value, int length, const char *tag)
{
    std::string output = ToHexString(value, length);

    Output(output, tag);
}

void CtriPOSOpenSSLHMACSampleDlg::Output(const char *value, const char *tag)
{
    std::string valueString(value);

    Output(valueString, tag);
}

void CtriPOSOpenSSLHMACSampleDlg::Output(std::string value, const char *tag)
{
    std::wstringstream output;

    if (tag != NULL)
    {
        output << tag;

        output << ": ";
    }

    output << value.c_str();

    output << "\r\n";

    int windowsTextLength = m_editOutput.GetWindowTextLengthW();

    m_editOutput.SetSel(windowsTextLength, windowsTextLength);

    m_editOutput.ReplaceSel(output.str().data());
}

void CtriPOSOpenSSLHMACSampleDlg::Output(int value, const char *tag)
{
    char output[16];

    sprintf(output, "%d", value);

    Output(output, tag);
}

std::string CtriPOSOpenSSLHMACSampleDlg::FixNewlinesForOutput(std::string value)
{
    std::string correctedValue(value);

    for (size_t newline = correctedValue.find("\n", 0); newline != std::string::npos;)
    {
        if (newline == 0 || correctedValue[newline - 1] != '\r')
        {
            correctedValue.insert(newline, "<0A>\r");

            newline += 5;
        }

        newline++;

        newline = correctedValue.find("\n", newline);
    }

    return correctedValue;
}

std::string CtriPOSOpenSSLHMACSampleDlg::ToHexString(const void *value, int length)
{
    std::string hexString;

    if (value != NULL && length > 0)
    {
        char hex[2 + 1];

        for (int index = 0; index < length; index++)
        {
            sprintf(hex, "%02x", ((unsigned char *)value)[index]);

            hexString += hex;
        }
    }

    return hexString;
}

std::string CtriPOSOpenSSLHMACSampleDlg::ToMultiByte(LPCTSTR wideChar)
{
    size_t length = WideCharToMultiByte(CP_OEMCP, 0, wideChar, -1, NULL, 0, NULL, NULL) + 1;

    char *buffer = (char *)calloc(length, 1);

    WideCharToMultiByte(CP_OEMCP, 0, wideChar, -1, buffer, length, NULL, NULL);

    std::string multiByte(buffer);

    free(buffer);

    return multiByte;
}

void CtriPOSOpenSSLHMACSampleDlg::ParseUri(std::wstring uri, std::string &scheme, std::string &host, std::string &port, std::string &path, std::string &query)
{
    size_t findIndex = uri.find(L"://", 0);

    if (findIndex != std::string::npos)
    {
        scheme.assign(ToMultiByte(uri.substr(0, findIndex).c_str()));

        findIndex += 3;

        uri.erase(0, findIndex);
    }

    findIndex = uri.find(L"/", 0);

    if (findIndex != std::string::npos)
    {
        host.assign(ToMultiByte(uri.substr(0, findIndex).c_str()));

        uri.erase(0, findIndex);

        if (!host.empty())
        {
            findIndex = host.find(":", 0);

            if (findIndex != std::string::npos)
            {
                port = host.substr(findIndex + 1);

                host.erase(findIndex);
            }
        }
    }

    findIndex = uri.find(L"?", 0);

    if (findIndex == std::string::npos)
    {
        path.assign(ToMultiByte(uri.c_str()));
    }
    else
    {
        path.assign(ToMultiByte(uri.substr(0, findIndex).c_str()));

        findIndex++;

        query.assign(ToMultiByte(uri.substr(findIndex).c_str()));
    }
}

std::string CtriPOSOpenSSLHMACSampleDlg::SortQuery(std::string query)
{
    if (query.empty())
    {
        return query;
    }

    std::stringstream queryStream(query);

    std::string queryPair;

    std::map<std::string, std::string> queryMap;

    while (std::getline(queryStream, queryPair, '&'))
    {
        if (!queryPair.empty())
        {
            size_t findIndex = queryPair.find("=", 0);

            std::pair<std::string, std::string> pair;

            if (findIndex == std::string::npos)
            {
                pair = std::make_pair(queryPair, "");
            }
            else
            {
                pair = std::make_pair(queryPair.substr(0, findIndex), queryPair.substr(findIndex + 1));
            }

            std::map<std::string, std::string>::iterator findIterator = queryMap.find(pair.first);

            if (findIterator == queryMap.end())
            {
                queryMap.insert(pair);
            }
            else
            {
                findIterator->second = pair.second;
            }
        }
    }

    std::string sortedQuery;

    for (std::map<std::string, std::string>::iterator queryListIterator = queryMap.begin(); queryListIterator != queryMap.end(); queryListIterator++)
    {
        if (!sortedQuery.empty())
        {
            sortedQuery += "&";
        }

        sortedQuery += queryListIterator->first;

        sortedQuery += "=";

        sortedQuery += queryListIterator->second;
    }

    return sortedQuery;
}

std::string ToLower(std::string &string)
{
    std::string lowerString(string);

    std::transform(lowerString.begin(), lowerString.end(), lowerString.begin(), ::tolower);

    return lowerString;
}

bool CompareNoCase(std::string &string1, std::string &string2)
{
    std::string s1(ToLower(string1));

    std::string s2(ToLower(string2));

    return s1.compare(s2) < 0;
}

std::string CtriPOSOpenSSLHMACSampleDlg::GetCanonicalSignedHeaders(std::wstring headers)
{
    std::stringstream headerStream(ToMultiByte(headers.c_str()));

    std::string header;

    std::list<std::string> headerList;

    while (std::getline(headerStream, header, '\n'))
    {
        header.pop_back();

        if (!header.empty() && (header.length() < 3 || _strnicmp(header.c_str(), "tp-", 3) != 0))
        {
            size_t findIndex = header.find(":", 0);

            if (findIndex != std::string::npos)
            {
                header.erase(findIndex);
            }

            header = Trim(header);

            header = ToLower(header);

            headerList.push_back(header);
        }
    }

    headerList.sort(CompareNoCase);

    std::string semiColonSeparatedHeaderList;

    for (std::list<std::string>::iterator headerListIterator = headerList.begin(); headerListIterator != headerList.end(); headerListIterator++)
    {
        if (!semiColonSeparatedHeaderList.empty())
        {
            semiColonSeparatedHeaderList += ";";
        }

        semiColonSeparatedHeaderList += *headerListIterator;
    }

    return semiColonSeparatedHeaderList;
}

struct MapCompareNoCase
{
    bool operator()(const std::string &string1, const std::string &string2) const
    {
        return CompareNoCase((const std::string)string1, (const std::string)string2);
    }
};

std::string CtriPOSOpenSSLHMACSampleDlg::GetCanonicalHeaders(std::wstring headers)
{
    std::stringstream headerStream(ToMultiByte(headers.c_str()));

    std::string header;

    std::map<std::string, std::string, MapCompareNoCase> headerMap;

    while (std::getline(headerStream, header, '\n'))
    {
        header = Trim(header, '\r');

        if (header.length() < 3 || _strnicmp(header.c_str(), "tp-", 3) != 0)
        {
            size_t findIndex = header.find(":", 0);

            std::pair<std::string, std::string> pair;

            if (findIndex == std::string::npos)
            {
                pair = std::make_pair(header, "");
            }
            else
            {
                pair = std::make_pair(header.substr(0, findIndex), header.substr(findIndex + 1));
            }

            pair.first = Trim(pair.first);

            pair.first = ToLower(pair.first);

            pair.second = Trim(pair.second);

            std::map<std::string, std::string>::iterator findIterator = headerMap.find(pair.first);

            if (findIterator == headerMap.end())
            {
                headerMap.insert(pair);
            }
            else
            {
                findIterator->second = pair.second;
            }
        }
    }

    std::string newlineSeparatedHeaderList;

    for (std::map<std::string, std::string>::iterator headerListIterator = headerMap.begin(); headerListIterator != headerMap.end(); headerListIterator++)
    {
        if (!newlineSeparatedHeaderList.empty())
        {
            newlineSeparatedHeaderList += "\n";
        }

        newlineSeparatedHeaderList += headerListIterator->first;

        newlineSeparatedHeaderList += ":";

        newlineSeparatedHeaderList += headerListIterator->second;
    }

    return newlineSeparatedHeaderList;
}

std::string CtriPOSOpenSSLHMACSampleDlg::HashValue(const void *value, int length, std::wstring algorithm)
{
    unsigned char hash[SHA_DIGEST_LENGTH];

    SHA1((const unsigned char *)value, length, hash);

    std::string hashHexString = ToHexString(hash, SHA_DIGEST_LENGTH);

    return hashHexString;
}

std::string CtriPOSOpenSSLHMACSampleDlg::KeyedHashValue(const void *value, int length, std::wstring algorithm, std::string key)
{
    unsigned char hash[HMAC_MAX_MD_CBLOCK];

    unsigned int hashLength;

    HMAC(EVP_sha1(), key.data(), key.length(), (const unsigned char*)value, length, hash, &hashLength);

    std::string hashHexString = ToHexString(hash, hashLength);

    return hashHexString;
}

std::string CtriPOSOpenSSLHMACSampleDlg::Trim(std::string string, char trimChar)
{
    size_t start;

    for (start = 0; start < string.length() && string[start] == trimChar; start++);

    size_t end;

    for (end = string.length(); end >= start && string[end - 1] == trimChar; end--);

    return string.substr(start, end - start);
}

// Send the request with hmac auth
void CtriPOSOpenSSLHMACSampleDlg::OnBnClickedButtonGo3()
{
	WCHAR *buffer;
	WSADATA wsaData;

	buffer = (WCHAR *)calloc(1024 + 1, sizeof(WCHAR));

	if (buffer == NULL)
	{
		Output("ERROR ALLOCATING BUFFER");

		return;
	}

	if (WSAStartup(0x0202, &wsaData) != 0) {
		AfxMessageBox(_T("WSAStartup() failed"));
		return;
	}

	const char ip[] = { "127.0.0.1" };
	int port = 8080;
	struct sockaddr_in serveraddr;
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = inet_addr(ip);
	serveraddr.sin_port = htons(port);

	int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		AfxMessageBox(_T("socket() failed"));
	}

	// Connect to server through socket
	if (connect(sock, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0)
	{
		AfxMessageBox(_T("connect() failed"));
	}

	// Build hmac auth headers
	std::string tpAuthorization = GenerateTPAuth();

	// Parse the URI
	m_editUri.GetWindowTextW(buffer, 1024);
	std::wstring wuri(buffer);
	std::string scheme;
	std::string host;
	std::string path;
	std::string query;
	std:string requestBody = ToMultiByte(body.c_str());
	ParseUri(wuri, scheme, host, std::to_string(port), path, query);

	// Get the method
	m_comboBoxMethod.GetLBText(m_comboBoxMethod.GetCurSel(), buffer);
	std::wstring wmethod(buffer);
	std::string method = ToMultiByte(wmethod.c_str());

	// Get the algorithm
	m_comboBoxAlgorithm.GetLBText(m_comboBoxAlgorithm.GetCurSel(), (LPTSTR)buffer);
	std::wstring walgorithm(buffer);
	std::string algorithm = ToMultiByte(walgorithm.c_str());

	// Build the request
	string request = method + " " + path + " HTTP/1.0\r\n";
	request += ToMultiByte(headers.c_str()) + "\r\n";
	request += "tp-authorization: " + tpAuthorization + "\r\n";
	request += "Content-Length: " + std::to_string(requestBody.length()) + "\r\n";
	request += "Connection: close\r\n";
	request += "\r\n";
	request += requestBody;
	request += "\r\n";

	// Send request
	if (send(sock, request.c_str(), request.length(), 0) != request.length()) {
		AfxMessageBox(_T("send() sent a different number of bytes than expected"));
	}

	//Get Response
	string response = "";
	int resp_leng = BUFFERSIZE;
	char buff[BUFFERSIZE];
	while (resp_leng > 0) {
		resp_leng = recv(sock, (char*)&buff, BUFFERSIZE, 0);
		if (resp_leng > 0) {
			response += string(buff).substr(0, resp_leng);
		}
	}

	// Remove BOM
	// The pattern \r\n\r\n indicates the end of the header
	string endOfHeader = "\r\n\r\n";
	// Obtain the substring before that pattern (the header)
	string header = response.substr(0, response.find(endOfHeader));
	// Obtain the length of the header minus one to get the index at which the header ends
	int indexOfContent = header.length() - 1;
	// Add 5 to the header index to skip the four endOfHeader chars and the one BOM char to get to the index of the first < in the content and extract the content
	string content = response.substr(indexOfContent + 5, response.length());
	// Put the response and header back together without the BOM chars to display it
	response = header + endOfHeader + content;

	// Close the connection and socket
	closesocket(sock);

	// Cleanup
	WSACleanup();

	std::wstringstream output;

	output << response.c_str();

	output << "\r\n";

	int windowsTextLength = m_editOutput.GetWindowTextLengthW();

	m_editOutput2.SetSel(windowsTextLength, windowsTextLength);

	m_editOutput2.ReplaceSel(output.str().data());
}
