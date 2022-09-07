/*
 * SignatureUtils.cpp
 * By Dalton Messmer
 */

#include "SignatureUtils.h"

#include <Windows.h>
//#include <wincrypt.h>
#include <atlconv.h>

#include <iostream>

static constexpr DWORD G_Encoding = (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING);

struct StoreWrapper
{
	StoreWrapper() : m_p(nullptr) {}
	StoreWrapper(HCERTSTORE p) : m_p(p) {}
	~StoreWrapper() { if (m_p) { CertCloseStore(m_p, 0); } }
	StoreWrapper(StoreWrapper&& other) { m_p = other.m_p; other.m_p = nullptr; }
	StoreWrapper(const StoreWrapper&) = delete;
	HCERTSTORE m_p;
};

struct MsgWrapper
{
	MsgWrapper() : m_p(nullptr) {}
	MsgWrapper(HCRYPTMSG p) : m_p(p) {}
	~MsgWrapper() { if (m_p) { CryptMsgClose(m_p); } }
	MsgWrapper(MsgWrapper&& other) { m_p = other.m_p; other.m_p = nullptr; }
	MsgWrapper(const MsgWrapper&) = delete;
	HCRYPTMSG m_p;
};

static bool GetCertStoreAndMsg(const std::string& filename, StoreWrapper& hStore, MsgWrapper& hMsg);
static PCCERT_CONTEXT GetCertContext(const std::string& filename);
static bool GetDigitalSignatureIssuerImpl(const std::string& filename, std::string& issuer);
static bool GetDigitalSignatureSubjectImpl(const std::string& filename, std::string& subject);

bool IsSigned(const std::string& filename)
{
	StoreWrapper hStore;
	MsgWrapper hMsg;
	return GetCertStoreAndMsg(filename, hStore, hMsg);
}

bool GetDigitalSignatureIssuer(const std::string& filename, std::string& issuer)
{
	__try
	{
		return GetDigitalSignatureIssuerImpl(filename, issuer);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return true;
	}
}

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

bool GetCertStoreAndMsg(const std::string& filename, StoreWrapper& hStore, MsgWrapper& hMsg)
{
	USES_CONVERSION;

	if (filename.empty() || filename[0] == 0)
		return nullptr;

	LPWSTR lpwszFileName = A2W(filename.c_str());
	if (lpwszFileName == NULL)
		return nullptr;

	return CryptQueryObject(CERT_QUERY_OBJECT_FILE, lpwszFileName, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY, 0, NULL, NULL, NULL, &hStore.m_p, &hMsg.m_p, NULL);
}

PCCERT_CONTEXT GetCertContext(const std::string& filename)
{
	StoreWrapper hStore;
	MsgWrapper hMsg;
	if (!GetCertStoreAndMsg(filename, hStore, hMsg))
		return nullptr; // The file is presumably not signed

	DWORD dwSignerInfo = 0;
	if (!CryptMsgGetParam(hMsg.m_p, CMSG_SIGNER_INFO_PARAM, 0, NULL, &dwSignerInfo) || !dwSignerInfo)
		return nullptr;

	PCMSG_SIGNER_INFO pSignerInfo = static_cast<PCMSG_SIGNER_INFO>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSignerInfo));
	if (!pSignerInfo)
		return nullptr;

	if (CryptMsgGetParam(hMsg.m_p, CMSG_SIGNER_INFO_PARAM, 0, pSignerInfo, &dwSignerInfo))
	{
		CERT_INFO ci;
		ci.Issuer = pSignerInfo->Issuer;
		ci.SerialNumber = pSignerInfo->SerialNumber;

		PCCERT_CONTEXT pCertContext = CertFindCertificateInStore(hStore.m_p, G_Encoding, 0, CERT_FIND_SUBJECT_CERT, &ci, NULL);
		HeapFree(GetProcessHeap(), 0, pSignerInfo);

		return pCertContext;
	}

	return nullptr;
}

bool GetDigitalSignatureIssuerImpl(const std::string& filename, std::string& issuer)
{
	issuer.clear();

	PCCERT_CONTEXT pCertContext = GetCertContext(filename);
	if (!pCertContext)
		return true;

	// Get issuer name size
	DWORD nameSize = CertGetNameStringA(pCertContext, CERT_NAME_ATTR_TYPE, CERT_NAME_ISSUER_FLAG, szOID_ORGANIZATION_NAME, NULL, 0);
	if (0 == nameSize)
		return true;

	// Allocate memory for issuer name
	LPSTR name = static_cast<LPSTR>(LocalAlloc(LPTR, nameSize * sizeof(CHAR)));

	// Get issuer name
	nameSize = CertGetNameStringA(pCertContext, CERT_NAME_ATTR_TYPE, CERT_NAME_ISSUER_FLAG, szOID_ORGANIZATION_NAME, name, nameSize);
	if (0 == nameSize || !name)
	{
		LocalFree(name);
		return true;
	}

	issuer = name;

	LocalFree(name);
	return false;
}

bool GetDigitalSignatureSubjectImpl(const std::string& filename, std::string& subject)
{
	subject.clear();

	PCCERT_CONTEXT pCertContext = GetCertContext(filename);
	if (!pCertContext)
		return true;

	// Get subject name size
	DWORD nameSize = CertGetNameStringA(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);
	if (0 == nameSize)
		return true;

	// Allocate memory for subject name
	LPSTR name = static_cast<LPSTR>(LocalAlloc(LPTR, nameSize * sizeof(CHAR)));

	// Get subject name
	nameSize = CertGetNameStringA(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, name, nameSize);
	if (0 == nameSize || !name)
	{
		LocalFree(name);
		return true;
	}

	subject = name;

	LocalFree(name);
	return false;
}
