# triPOS.Cpp

* Questions?  certification@elementps.com
* **Feature request?** Open an issue.
* Feel like **contributing**?  Submit a pull request.


### This sample demonstrates HMAC header signing with C++


##Prerequisites

Please contact your Integration Analyst for any questions about the below prerequisites.

* Register and download the triPOS application: https://mft.elementps.com/backend/plugin/Registration/ (once activated, login at https://mft.elementps.com)
* Create Express test account: http://www.elementps.com/Resources/Create-a-Test-Account
* Install and configure triPOS
* Optionally install a hardware peripheral and obtain test cards (but you can be up and running without hardware for testing purposes)
* Currently triPOS is supported on Windows 7
* Install OpenSsl for windows (You can build your own or get pre-compiled versions [here](http://www.npcglib.org/~stathis/blog/precompiled-openssl/)
* In Visual Studio add your openssl headers to the include directories i.e. `C:\openssl\include` 
* In Visual Studio add to the linker the openssl additional include directories i.e. `C:\OpenSSL\OpenSSL-Win32\lib\VC\static`

##Documentation/Troubleshooting

* To view the triPOS embedded API documentation point your favorite browser to:  http://localhost:8080/help/ (for a default install).”
* In addition to the help documentation above triPOS writes information to a series of log files located at:  C:\Program Files (x86)\Vantiv\triPOS Service\Logs (for a default install).
* If you are having trouble building the project, ensure you have openssl installed correctly on windows and you have included openssl headers and link files as mentioned above in the prerequisites

##Step 1: Generate a request package

The sample pre-populates the JSON body and a default set of headers. Notice that the value in laneId is 9999.  This is the 'null' laneId meaning a transaction will flow through the system without requiring hardware.  All lanes are configured in the triPOS.config file located at:  C:\Program Files (x86)\Vantiv\triPOS Service (if you kept the default installation directory).  If you modify this file make sure to restart the triPOS.NET service in the Services app to read in your latest triPOS.config changes.

`Sample Body:`

```
{"address":null,"transactionAmount":1.0000,"clerkNumber":null,"configuration":{"AllowPartialApprovals":false,"CheckForDuplicateTransactions":true,"CurrencyCode":"Usd","MarketCode":"Retail"},"laneId":9999,"referenceNumber":"SRef1634","shiftId":"Store","ticketNumber":"1634"}
```

`Default Headers:`

```
accept:*/*
accept-encoding:gzip, deflate
accept-language:en-US
cache-control:no-cache
connection:Keep-Alive
cookie:ASP.NET_SessionId=rgxa234xzzj5l1jabpa2tpyw
dnt:1
host:localhost:8080
referer:http://www.ezprocessingsoftware.com:8006/EzCharge/Vantiv/ProcessSale?systemId=CRID-145&MerchantId=3928907&paymentAmount=1.0000&Token=91320f68d6004c9798f45219228865cf&duplicate=0&locationId=2
user-agent:Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko
```

##Step 2: Run the hmac authorization header creation
It is very helpful to look over the code while following along with the integration guide.

* Note the algorithm to be used in this case is SHA-1
* Choose your requet mechanism (POST/PUT/GET/DELETE) and select the approriate endpoint i.e. `http://localhost:8080/api/v1/sale`
* Note the nonce generation using a standard GUID (this is pre-populated)
* Supply your developer key and secret into the provided form fields
* When ready click `Go` and this will build up the HMAC authorization string as noted in the integration guide titled: `HMAC authorization header (tp-authorization)`

####This will use the given data to build up the authorization string as viewed in the `OnBnClickedButtonGo` method

```
void CtriPOSOpenSSLHMACSampleDlg::OnBnClickedButtonGo()
{
    OutputClear();

    WCHAR *buffer;

    buffer = (WCHAR *)calloc(1024 + 1, sizeof(WCHAR));

    if (buffer == NULL)
    {
        Output("ERROR ALLOCATING BUFFER");

        return;
    }

    m_comboBoxMethod.GetLBText(m_comboBoxMethod.GetCurSel(), buffer);

    std::wstring method(buffer);

    m_comboBoxAlgorithm.GetLBText(m_comboBoxAlgorithm.GetCurSel(), (LPTSTR)buffer);

    std::wstring algorithm(buffer);

    m_editVersion.GetWindowTextW(buffer, 1024);

    std::wstring version(buffer);

    m_editRequestDate.GetWindowTextW(buffer, 1024);

    std::wstring requestDate(buffer);

    m_editUri.GetWindowTextW(buffer, 1024);

    std::wstring uri(buffer);

    m_editNonce.GetWindowTextW(buffer, 1024);

    std::wstring nonce(buffer);

    m_editDeveloperKey.GetWindowTextW(buffer, 1024);

    std::wstring developerKey(buffer);

    m_editDeveloperSecret.GetWindowTextW(buffer, 1024);

    std::wstring developerSecret(buffer);

    free(buffer);

    int length = m_editHeaders.GetWindowTextLengthW() + 1;

    buffer = (WCHAR *)calloc(length, sizeof(WCHAR));

    if (buffer == NULL)
    {
        Output("ERROR ALLOCATING HEADERS BUFFER");
    }

    m_editHeaders.GetWindowTextW(buffer, length);

    std::wstring headers(buffer);

    free(buffer);

    length = m_editBody.GetWindowTextLengthW() + 1;

    buffer = (WCHAR *)calloc(length, sizeof(WCHAR));

    if (buffer == NULL)
    {
        Output("ERROR ALLOCATING BODY BUFFER");
    }

    m_editBody.GetWindowTextW(buffer, length);

    std::wstring body(buffer);

    free(buffer);

    std::string hashedCanonicalRequest = HashCanonicalRequest(method, uri, headers, body, algorithm);

    std::string signingKey = CreateSigningKey(requestDate, nonce, developerSecret, algorithm);

    std::string requestSignature = CreateRequestSignature(requestDate, developerKey, hashedCanonicalRequest, signingKey, algorithm);

    std::string tpAuthorizationHeader = CreateTpAuthorizationHeader(version, developerKey, headers, nonce, requestDate, requestSignature, algorithm);
}

```

##Final steps 

Final steps would be to send the request on to your designated endpoint for your request and parse the response data.

###©2015-2016 Element Payment Services, Inc., a Vantiv company. All Rights Reserved.

Disclaimer:
This software and all specifications and documentation contained herein or provided to you hereunder (the "Software") are provided free of charge strictly on an "AS IS" basis. No representations or warranties are expressed or implied, including, but not limited to, warranties of suitability, quality, merchantability, or fitness for a particular purpose (irrespective of any course of dealing, custom or usage of trade), and all such warranties are expressly and specifically disclaimed. Element Payment Services, Inc., a Vantiv company, shall have no liability or responsibility to you nor any other person or entity with respect to any liability, loss, or damage, including lost profits whether foreseeable or not, or other obligation for any cause whatsoever, caused or alleged to be caused directly or indirectly by the Software. Use of the Software signifies agreement with this disclaimer notice.


 