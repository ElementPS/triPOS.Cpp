
// triPOS OpenSSL HMAC Sample.h : main header file for the PROJECT_NAME application
//

#pragma once

#ifndef __AFXWIN_H__
	#error "include 'stdafx.h' before including this file for PCH"
#endif

#include "resource.h"		// main symbols


// CtriPOSOpenSSLHMACSampleApp:
// See triPOS OpenSSL HMAC Sample.cpp for the implementation of this class
//

class CtriPOSOpenSSLHMACSampleApp : public CWinApp
{
public:
	CtriPOSOpenSSLHMACSampleApp();

// Overrides
public:
	virtual BOOL InitInstance();

// Implementation

	DECLARE_MESSAGE_MAP()
};

extern CtriPOSOpenSSLHMACSampleApp theApp;