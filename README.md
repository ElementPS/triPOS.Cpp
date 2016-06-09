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
Note that this just generates the header information for viewing (step 3 will send a real request)

* Note the algorithm to be used in this case is SHA-1
* Choose your requet mechanism (POST/PUT/GET/DELETE) and select the approriate endpoint i.e. `http://localhost:8080/api/v1/sale`
* Note the nonce generation using a standard GUID (this is pre-populated)
* Supply your developer key and secret into the provided form fields
* When ready click `Go` and this will build up the HMAC authorization string as noted in the integration guide titled: `HMAC authorization header (tp-authorization)`

####This will use the given data to build up the authorization string as viewed in the `GenerateTPAuth` method

```
std::string CtriPOSOpenSSLHMACSampleDlg::GenerateTPAuth()
{
  OutputClear();

  CollectInput();

  std::string hashedCanonicalRequest = HashCanonicalRequest(method, uri, headers, body, algorithm);

  std::string signingKey = CreateSigningKey(requestDate, nonce, developerSecret, algorithm);

  std::string requestSignature = CreateRequestSignature(requestDate, developerKey, hashedCanonicalRequest, signingKey, algorithm);

  return CreateTpAuthorizationHeader(version, developerKey, headers, nonce, requestDate, requestSignature, algorithm);
}
```

##Step 3: Send the request 
Note that this builds the data on its own (apart from the header generation demonstration in part 2)
```
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
```



###©2015-2016 Element Payment Services, Inc., a Vantiv company. All Rights Reserved.

Disclaimer:
This software and all specifications and documentation contained herein or provided to you hereunder (the "Software") are provided free of charge strictly on an "AS IS" basis. No representations or warranties are expressed or implied, including, but not limited to, warranties of suitability, quality, merchantability, or fitness for a particular purpose (irrespective of any course of dealing, custom or usage of trade), and all such warranties are expressly and specifically disclaimed. Element Payment Services, Inc., a Vantiv company, shall have no liability or responsibility to you nor any other person or entity with respect to any liability, loss, or damage, including lost profits whether foreseeable or not, or other obligation for any cause whatsoever, caused or alleged to be caused directly or indirectly by the Software. Use of the Software signifies agreement with this disclaimer notice.


 