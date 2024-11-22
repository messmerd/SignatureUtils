/*
 * SignatureUtils.cpp
 * By Dalton Messmer
 */

#include "SignatureUtils/SignatureUtils.h"

#include <Windows.h>
#include <atlconv.h>

#include <string_view>

using namespace sigutils;

static constexpr DWORD G_Encoding = (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING);

struct StoreWrapper
{
	StoreWrapper() : p(nullptr) {}
	StoreWrapper(HCERTSTORE p_in) : p(p_in) {}
	~StoreWrapper() { if (p) { CertCloseStore(p, 0); } }
	StoreWrapper(StoreWrapper&& other) { p = other.p; other.p = nullptr; }
	StoreWrapper(const StoreWrapper&) = delete;
	HCERTSTORE p;
};

struct MsgWrapper
{
	MsgWrapper() : p(nullptr) {}
	MsgWrapper(HCRYPTMSG p_in) : p(p_in) {}
	~MsgWrapper() { if (p) { CryptMsgClose(p); } }
	MsgWrapper(MsgWrapper&& other) { p = other.p; other.p = nullptr; }
	MsgWrapper(const MsgWrapper&) = delete;
	HCRYPTMSG p;
};

static bool GetCertStoreAndMsg(const std::string& filename, StoreWrapper& hStore, MsgWrapper& hMsg);
static PCCERT_CONTEXT GetCertContext(const std::string& filename);
static std::optional<CertInfo> GetSubjectOrIssuer(const std::string& filename, bool getIssuer);
static CertInfo ParseCertInfo(const std::string& input, const std::string& delimiter);

////// PUBLIC FUNCTIONS //////

bool sigutils::IsSigned(const std::string& filename)
{
	StoreWrapper hStore;
	MsgWrapper hMsg;
	return GetCertStoreAndMsg(filename, hStore, hMsg);
}

std::optional<CertInfo> sigutils::GetIssuer(const std::string& filename)
{
	return GetSubjectOrIssuer(filename, true);
}

std::optional<CertInfo> sigutils::GetSubject(const std::string& filename)
{
	return GetSubjectOrIssuer(filename, false);
}

std::optional<std::string> sigutils::GetIssuerName(const std::string& filename)
{
	PCCERT_CONTEXT pCertContext = GetCertContext(filename);
	if (!pCertContext)
		return std::nullopt;

	// Get issuer name size
	DWORD nameSize = CertGetNameStringA(pCertContext, CERT_NAME_ATTR_TYPE, CERT_NAME_ISSUER_FLAG, szOID_ORGANIZATION_NAME, NULL, 0);
	if (0 == nameSize)
		return std::nullopt;

	// Allocate memory for issuer name
	LPSTR name = static_cast<LPSTR>(LocalAlloc(LPTR, nameSize * sizeof(CHAR)));

	// Get issuer name
	nameSize = CertGetNameStringA(pCertContext, CERT_NAME_ATTR_TYPE, CERT_NAME_ISSUER_FLAG, szOID_ORGANIZATION_NAME, name, nameSize);
	if (0 == nameSize || !name)
	{
		LocalFree(name);
		return std::nullopt;
	}

	std::string issuer = name;
	LocalFree(name);
	return issuer;
}

std::optional<std::string> sigutils::GetSubjectName(const std::string& filename)
{
	PCCERT_CONTEXT pCertContext = GetCertContext(filename);
	if (!pCertContext)
		return std::nullopt;

	// Get subject name size
	DWORD nameSize = CertGetNameStringA(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);
	if (0 == nameSize)
		return std::nullopt;

	// Allocate memory for subject name
	LPSTR name = static_cast<LPSTR>(LocalAlloc(LPTR, nameSize * sizeof(CHAR)));

	// Get subject name
	nameSize = CertGetNameStringA(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, name, nameSize);
	if (0 == nameSize || !name)
	{
		LocalFree(name);
		return std::nullopt;
	}

	std::string subject = name;
	LocalFree(name);
	return subject;
}

////// Helpers //////

bool GetCertStoreAndMsg(const std::string& filename, StoreWrapper& hStore, MsgWrapper& hMsg)
{
	USES_CONVERSION;

	if (filename.empty() || filename[0] == 0)
		return nullptr;

	LPWSTR lpwszFileName = A2W(filename.c_str());
	if (lpwszFileName == NULL)
		return nullptr;

	return CryptQueryObject(CERT_QUERY_OBJECT_FILE, lpwszFileName, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
		CERT_QUERY_FORMAT_FLAG_BINARY, 0, NULL, NULL, NULL, &hStore.p, &hMsg.p, NULL);
}

PCCERT_CONTEXT GetCertContext(const std::string& filename)
{
	StoreWrapper hStore;
	MsgWrapper hMsg;
	if (!GetCertStoreAndMsg(filename, hStore, hMsg))
		return nullptr; // The file is presumably not signed

	DWORD dwSignerInfo = 0;
	if (!CryptMsgGetParam(hMsg.p, CMSG_SIGNER_INFO_PARAM, 0, NULL, &dwSignerInfo) || !dwSignerInfo)
		return nullptr;

	PCMSG_SIGNER_INFO pSignerInfo = static_cast<PCMSG_SIGNER_INFO>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSignerInfo));
	if (!pSignerInfo)
		return nullptr;

	if (CryptMsgGetParam(hMsg.p, CMSG_SIGNER_INFO_PARAM, 0, pSignerInfo, &dwSignerInfo))
	{
		CERT_INFO ci;
		ci.Issuer = pSignerInfo->Issuer;
		ci.SerialNumber = pSignerInfo->SerialNumber;

		PCCERT_CONTEXT pCertContext = CertFindCertificateInStore(hStore.p, G_Encoding, 0, CERT_FIND_SUBJECT_CERT, &ci, NULL);
		HeapFree(GetProcessHeap(), 0, pSignerInfo);

		return pCertContext;
	}

	return nullptr;
}

CertInfo ParseCertInfo(const std::string& input, const std::string& delimiter)
{
	CertInfo info;
	auto input_view = std::string_view(input);

	size_t start = 0;
	size_t end = input_view.find(delimiter);
	while (end != std::string_view::npos)
	{
		const auto entry = input_view.substr(start, end - start);

		start = end + delimiter.length();
		end = input.find(delimiter, start);

		size_t equalsPos = entry.find('=');
		if (equalsPos == std::string_view::npos || equalsPos == 0)
			continue;

		const auto x500 = entry.substr(0, equalsPos);
		auto rdn = entry.substr(equalsPos + 1);
		if (rdn.empty())
			continue;
		if (rdn[0] == '=')
			rdn = rdn.substr(1, rdn.size() - 2);

		if (x500.size() > 1)
		{
			if (x500 == "CN")
			{
				info.CN = rdn;
			}
			else if (x500 == "OU")
			{
				info.OU = rdn;
			}
		}
		else switch (x500[0])
		{
		case 'O':
			info.O = rdn;
			break;
		case 'L':
			info.L = rdn;
			break;
		case 'S':
			info.S = rdn;
			break;
		case 'C':
			info.C = rdn;
			break;
		default:
			break;
		}
	}

	return info;
}

std::optional<CertInfo> GetSubjectOrIssuer(const std::string& filename, bool getIssuer)
{
	PCCERT_CONTEXT pCertContext = GetCertContext(filename);
	if (!pCertContext)
		return std::nullopt;

	DWORD dwStrType = CERT_X500_NAME_STR | CERT_NAME_STR_CRLF_FLAG;
	DWORD dwFlags = getIssuer ? CERT_NAME_ISSUER_FLAG : 0;

	// Get RDN string
	DWORD nameSize = CertGetNameStringA(pCertContext, CERT_NAME_RDN_TYPE, dwFlags, &dwStrType, NULL, 0);
	if (0 == nameSize)
		return std::nullopt;

	// Allocate memory for RDN string
	LPSTR name = static_cast<LPSTR>(LocalAlloc(LPTR, nameSize * sizeof(CHAR)));

	// Get RDN string
	nameSize = CertGetNameStringA(pCertContext, CERT_NAME_RDN_TYPE, dwFlags, &dwStrType, name, nameSize);
	if (0 == nameSize || !name)
	{
		LocalFree(name);
		return std::nullopt;
	}

	const std::string delimiter = "\r\n";
	std::string x500PlusRDN = name + delimiter;
	LocalFree(name);

	return ParseCertInfo(x500PlusRDN, delimiter);
}
