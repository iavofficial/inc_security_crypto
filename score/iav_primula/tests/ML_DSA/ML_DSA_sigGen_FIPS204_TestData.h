// Generated from JSON file: ML-DSA-sigGen-FIPS204\internalProjection.json
#include <string>
#include <vector>

// Test case struct
struct ML_DSA_sigGen_TestCase
{
  std::string context;
  bool deferred;
  std::string hashAlg;
  std::string message;
  std::string mu;
  std::string pk;
  std::string rnd;
  std::string signature;
  std::string sk;
  int tcId;
};

// Test group struct
struct ML_DSA_sigGen_TestGroup
{
  std::string cornerCase;
  bool deterministic;
  bool externalMu;
  std::string parameterSet;
  std::string preHash;
  std::string signatureInterface;
  std::string testType;
  int tgId;
  std::vector<ML_DSA_sigGen_TestCase> tests;
};

extern std::vector<ML_DSA_sigGen_TestGroup> ML_DSA_sigGen_testGroups;