// Generated from JSON file: ML-DSA-sigVer-FIPS204\internalProjection.json
#include <string>
#include <vector>

// Test case struct
struct ML_DSA_sigVer_TestCase
{
  std::string context;
  bool deferred;
  std::string hashAlg;
  std::string message;
  std::string mu;
  std::string pk;
  std::string reason;
  std::string signature;
  std::string sk;
  int tcId;
  bool testPassed;
};

// Test group struct
struct ML_DSA_sigVer_TestGroup
{
  bool externalMu;
  std::string parameterSet;
  std::string preHash;
  std::string signatureInterface;
  std::string testType;
  int tgId;
  std::vector<ML_DSA_sigVer_TestCase> tests;
};

extern std::vector<ML_DSA_sigVer_TestGroup> ML_DSA_sigVer_testGroups;