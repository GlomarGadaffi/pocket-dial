#include "GoogleServiceAuth.hpp"

#include "SmtpDialogue.hpp" // base64UrlEncode
#include "JsonEscape.hpp"
#include "UrlEncode.hpp"

#include <cstdio>
#include <mutex>
#include <vector>

#if defined(ESP_PLATFORM) || defined(ESP32)
	#include "mbedtls/pk.h"
	#include "mbedtls/md.h"
	#include "esp_http_client.h"
	#include "esp_crt_bundle.h"
	#include "esp_log.h"
	#include "cJSON.h"
	#include "TimeSync.hpp"
	static const char* kTag = "GoogleServiceAuth";
#elif defined(PD_HAVE_OPENSSL)
	#include <openssl/evp.h>
	#include <openssl/pem.h>
	#include <openssl/bio.h>
#endif

namespace GoogleServiceAuth
{

std::string buildHeaderJson()
{
	return "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
}

std::string buildClaimsJson(const std::string& iss, const std::string& sub,
                             const std::string& scope, const std::string& aud,
                             uint64_t iat, uint64_t exp)
{
	std::string j = "{";
	j += "\"iss\":\"" + jsonEscapeString(iss) + "\",";
	j += "\"sub\":\"" + jsonEscapeString(sub) + "\",";
	j += "\"scope\":\"" + jsonEscapeString(scope) + "\",";
	j += "\"aud\":\"" + jsonEscapeString(aud) + "\",";
	char nums[64];
	std::snprintf(nums, sizeof(nums), "\"iat\":%llu,\"exp\":%llu",
	              static_cast<unsigned long long>(iat), static_cast<unsigned long long>(exp));
	j += nums;
	j += "}";
	return j;
}

#if defined(ESP_PLATFORM) || defined(ESP32)

bool signRs256(const std::string& privateKeyPem, const std::string& signingInput,
                std::string& signatureOut, std::string& errOut)
{
	mbedtls_pk_context pk;
	mbedtls_pk_init(&pk);

	// PEM parsing requires the buffer to be NUL-terminated and keylen to
	// include that terminator (mbedtls_pk_parse_key's own contract).
	int rc = mbedtls_pk_parse_key(&pk, reinterpret_cast<const unsigned char*>(privateKeyPem.c_str()),
	                                privateKeyPem.size() + 1, nullptr, 0);
	if (rc != 0)
	{
		mbedtls_pk_free(&pk);
		errOut = "failed to parse service-account private key (mbedtls -0x" + std::to_string(-rc) + ")";
		return false;
	}

	unsigned char hash[32];
	rc = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
	                 reinterpret_cast<const unsigned char*>(signingInput.data()), signingInput.size(), hash);
	if (rc != 0)
	{
		mbedtls_pk_free(&pk);
		errOut = "SHA-256 of signing input failed";
		return false;
	}

	unsigned char sig[MBEDTLS_PK_SIGNATURE_MAX_SIZE];
	size_t sigLen = 0;
	rc = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, sizeof(hash), sig, sizeof(sig), &sigLen);
	mbedtls_pk_free(&pk);
	if (rc != 0)
	{
		errOut = "RSA-SHA256 signing failed (mbedtls -0x" + std::to_string(-rc) + ") -- is the key an RSA key?";
		return false;
	}

	signatureOut.assign(reinterpret_cast<const char*>(sig), sigLen);
	return true;
}

#elif defined(PD_HAVE_OPENSSL) // host build -- OpenSSL

bool signRs256(const std::string& privateKeyPem, const std::string& signingInput,
                std::string& signatureOut, std::string& errOut)
{
	BIO* bio = BIO_new_mem_buf(privateKeyPem.data(), static_cast<int>(privateKeyPem.size()));
	if (bio == nullptr)
	{
		errOut = "BIO_new_mem_buf failed";
		return false;
	}
	EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
	BIO_free(bio);
	if (pkey == nullptr)
	{
		errOut = "failed to parse service-account private key PEM";
		return false;
	}

	bool ok = false;
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	std::vector<unsigned char> sig;
	if (ctx != nullptr)
	{
		size_t sigLen = 0;
		if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) == 1 &&
		    EVP_DigestSignUpdate(ctx, signingInput.data(), signingInput.size()) == 1 &&
		    EVP_DigestSignFinal(ctx, nullptr, &sigLen) == 1)
		{
			sig.resize(sigLen);
			if (EVP_DigestSignFinal(ctx, sig.data(), &sigLen) == 1)
			{
				sig.resize(sigLen);
				ok = true;
			}
		}
		EVP_MD_CTX_free(ctx);
	}
	EVP_PKEY_free(pkey);

	if (!ok)
	{
		errOut = "RSA-SHA256 signing failed -- is the key an RSA key?";
		return false;
	}
	signatureOut.assign(reinterpret_cast<const char*>(sig.data()), sig.size());
	return true;
}

#else // host build with no crypto backend configured

// A host build that could not find OpenSSL. The rest of this file -- the JWT
// header and claims construction, which is where the escaping and exact-shape
// bugs actually live -- is pure string work and still compiles, still runs and
// is still tested. Only the signature is unavailable.
//
// This arm exists so that a Windows host build without OpenSSL CONFIGURES AND
// BUILDS rather than dying at cmake time, which is what `find_package(OpenSSL
// REQUIRED)` used to do on a platform CONTRIBUTING_FIRMWARE.md lists as
// supported. Failing loudly at the one call that cannot work beats failing at
// configure for the whole project.
//
// Nothing on the DEVICE reaches here: ESP builds take the mbedTLS arm above,
// and the XOAUTH2 token fetch is ESP-only regardless.
bool signRs256(const std::string& /*privateKeyPem*/, const std::string& /*signingInput*/,
                std::string& /*signatureOut*/, std::string& errOut)
{
	errOut = "RS256 signing unavailable: this host build was configured without "
	         "OpenSSL (see CONTRIBUTING_FIRMWARE.md)";
	return false;
}

#endif

bool buildSignedJwt(const std::string& serviceAccountEmail, const std::string& subjectUser,
                     const std::string& scope, const std::string& privateKeyPem,
                     uint64_t nowUnix, std::string& jwtOut, std::string& errOut)
{
	if (serviceAccountEmail.empty() || subjectUser.empty() || scope.empty() || privateKeyPem.empty())
	{
		errOut = "service account email, subject user, scope and private key are all required";
		return false;
	}

	static const char* kAudience = "https://oauth2.googleapis.com/token";
	static const uint64_t kLifetimeSec = 3600; // Google's fixed maximum for this grant type

	std::string headerJson = buildHeaderJson();
	std::string claimsJson = buildClaimsJson(serviceAccountEmail, subjectUser, scope, kAudience,
	                                          nowUnix, nowUnix + kLifetimeSec);

	std::string signingInput =
		SmtpDialogue::base64UrlEncode(reinterpret_cast<const uint8_t*>(headerJson.data()), headerJson.size()) +
		"." +
		SmtpDialogue::base64UrlEncode(reinterpret_cast<const uint8_t*>(claimsJson.data()), claimsJson.size());

	std::string signature;
	if (!signRs256(privateKeyPem, signingInput, signature, errOut))
	{
		return false;
	}

	jwtOut = signingInput + "." +
	         SmtpDialogue::base64UrlEncode(reinterpret_cast<const uint8_t*>(signature.data()), signature.size());
	return true;
}

#if defined(ESP_PLATFORM) || defined(ESP32)

namespace
{
	std::mutex g_cacheMutex;
	std::string g_cacheKey;
	std::string g_cachedToken;
	uint64_t g_cachedExpiry = 0; // unix seconds; 0 = nothing cached
}

bool getAccessToken(const std::string& serviceAccountEmail, const std::string& subjectUser,
                     const std::string& scope, const std::string& privateKeyPem,
                     std::string& accessTokenOut, std::string& errOut)
{
	std::string cacheKey = serviceAccountEmail + "|" + subjectUser + "|" + scope;
	uint64_t now = timesync::epochSeconds();

	{
		std::lock_guard<std::mutex> lk(g_cacheMutex);
		// 60 s safety margin before the token's real expiry -- a send that
		// starts just before expiry must not present a token that dies
		// mid-conversation.
		if (g_cacheKey == cacheKey && now > 0 && g_cachedExpiry > now + 60)
		{
			accessTokenOut = g_cachedToken;
			return true;
		}
	}

	if (now == 0)
	{
		errOut = "device clock is not synced (SNTP) -- cannot mint a valid JWT";
		return false;
	}

	std::string jwt, jwtErr;
	if (!buildSignedJwt(serviceAccountEmail, subjectUser, scope, privateKeyPem, now, jwt, jwtErr))
	{
		errOut = "JWT build failed: " + jwtErr;
		return false;
	}

	esp_http_client_config_t config = {};
	config.url = "https://oauth2.googleapis.com/token";
	config.method = HTTP_METHOD_POST;
	config.crt_bundle_attach = esp_crt_bundle_attach;
	config.buffer_size = 2048;
	config.timeout_ms = 10000;
	esp_http_client_handle_t client = esp_http_client_init(&config);
	if (client == nullptr)
	{
		errOut = "esp_http_client_init failed";
		return false;
	}

	std::string body = "grant_type=" + urlEncode("urn:ietf:params:oauth:grant-type:jwt-bearer") +
	                    "&assertion=" + urlEncode(jwt);
	esp_http_client_set_header(client, "Content-Type", "application/x-www-form-urlencoded");
	esp_http_client_set_post_field(client, body.c_str(), static_cast<int>(body.size()));

	esp_err_t err = esp_http_client_perform(client);
	if (err != ESP_OK)
	{
		errOut = std::string("token request failed: ") + esp_err_to_name(err);
		esp_http_client_cleanup(client);
		return false;
	}

	int status = esp_http_client_get_status_code(client);
	std::string respBody;
	char buf[512];
	int n;
	while ((n = esp_http_client_read(client, buf, sizeof(buf))) > 0)
	{
		respBody.append(buf, static_cast<size_t>(n));
	}
	esp_http_client_cleanup(client);

	if (status < 200 || status >= 300)
	{
		ESP_LOGW(kTag, "token endpoint HTTP %d: %s", status, respBody.c_str());
		errOut = "token endpoint returned HTTP " + std::to_string(status);
		return false;
	}

	cJSON* root = cJSON_Parse(respBody.c_str());
	if (root == nullptr)
	{
		errOut = "malformed token response JSON";
		return false;
	}
	cJSON* tok = cJSON_GetObjectItemCaseSensitive(root, "access_token");
	cJSON* exp = cJSON_GetObjectItemCaseSensitive(root, "expires_in");
	if (!cJSON_IsString(tok) || tok->valuestring == nullptr)
	{
		errOut = "token response missing access_token";
		cJSON_Delete(root);
		return false;
	}
	accessTokenOut = tok->valuestring;
	uint64_t expiresIn = cJSON_IsNumber(exp) ? static_cast<uint64_t>(exp->valuedouble) : 3600;
	cJSON_Delete(root);

	{
		std::lock_guard<std::mutex> lk(g_cacheMutex);
		g_cacheKey = cacheKey;
		g_cachedToken = accessTokenOut;
		g_cachedExpiry = now + expiresIn;
	}
	return true;
}

#endif // ESP_PLATFORM

} // namespace GoogleServiceAuth
