// By Dalton Messmer

#include "SignatureUtils.h"

#include <wincrypt.h>
#include <atlconv.h>

#pragma comment(lib, "wincrypt")

static constexpr DWORD G_Encoding = (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING);

static bool GetDigitalSignatureSubjectImpl(const std::string& filename, std::string& subject);

bool GetDigitalSignatureSubject(const std::string& filename, std::string& subject)
{
	__try
	{
		return GetDigitalSignatureSubjectImpl(filename, subject);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return true;
	}
}

bool GetDigitalSignatureSubjectImpl(const std::string& filename, std::string& subject)
{
	USES_CONVERSION;
	subject.clear();

	if (filename.empty())
		return true;

	if (filename[0] == 0)
		return true;

	LPWSTR lpwszFileName = A2W(filename.c_str());
	if (lpwszFileName == NULL)
		return true;

	bool error = true;
	LPSTR szName = NULL;
	HCERTSTORE hStore = NULL;
	HCRYPTMSG hMsg = NULL;
	PCMSG_SIGNER_INFO pSignerInfo = nullptr;

	if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, lpwszFileName, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY, 0, NULL, NULL, NULL, &hStore, &hMsg, NULL))
		goto cleanup; // The file is presumably not signed

	DWORD dwSignerInfo = 0;
	if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &dwSignerInfo) && (dwSignerInfo != 0))
	{
		pSignerInfo = static_cast<PCMSG_SIGNER_INFO>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSignerInfo));
	}

	if (!pSignerInfo)
		goto cleanup;

	if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, pSignerInfo, &dwSignerInfo))
	{
		CERT_INFO ci;
		ci.Issuer = pSignerInfo->Issuer;
		ci.SerialNumber = pSignerInfo->SerialNumber;

		PCCERT_CONTEXT const pCertContext = CertFindCertificateInStore(hStore, G_Encoding, 0, CERT_FIND_SUBJECT_CERT, &ci, NULL);
		if (!pCertContext)
			goto cleanup;

		// Get subject name size
		DWORD dwData = CertGetNameStringA(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);
		if (0 == dwData)
			goto cleanup;

		// Allocate memory for subject name
		szName = static_cast<LPSTR>(LocalAlloc(LPTR, dwData * sizeof(CHAR)));
		if (!szName)
			goto cleanup;

		// Get subject name
		dwData = CertGetNameStringA(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, szName, dwData);
		if (0 == dwData)
			goto cleanup;

		if (NULL != szName)
		{
			// Success!
			subject = szName;
			error = false;
		}
	}

cleanup:

	if (szName != NULL)
		LocalFree(szName);

	if (pSignerInfo != NULL)
		HeapFree(GetProcessHeap(), 0, pSignerInfo);

	if (hStore != NULL)
		CertCloseStore(hStore, 0);

	if (hMsg != NULL)
		CryptMsgClose(hMsg);

	return error;
}
