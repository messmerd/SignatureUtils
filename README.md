# SignatureUtils
### Windows digital signature utils

Wincrypt is ugly, painful to work with, and confusing, so I created this project in modern C++ as a way to avoid directly using it for simple queries about Windows digital signatures.

Currently provides the following functions:
```C++
bool IsSigned(const std::string& filename);

std::optional<CertInfo> GetIssuer(const std::string& filename);
std::optional<CertInfo> GetSubject(const std::string& filename);

std::optional<std::string> GetIssuerName(const std::string& filename);
std::optional<std::string> GetSubjectName(const std::string& filename);
```
______
Created by Dalton Messmer <messmer.dalton(at)gmail(dot)com>.
