/*
 * SignatureUtils.h
 * By Dalton Messmer
 */

#pragma once

#include <string>

bool IsSigned(const std::string& filename);
bool GetDigitalSignatureIssuer(const std::string& filename, std::string& issuer);
bool GetDigitalSignatureSubject(const std::string& filename, std::string& subject);
