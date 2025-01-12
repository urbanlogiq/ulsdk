# UrbanLogiq SDK

## Authentication

All access to UrbanLogiq systems requires some sort of authentication, typically with signed requests using API keys.

The API keys contain a private key and a key ID. The private key is used to sign the requests and must be kept secret. Please do not deploy API keys in plain text to user applications or public repositories.

API keys can be managed through our API key portal:
* [US environments](https://home.urbanlogiq.us/admin/keys)
* [Canadian environments](https://home.urbanlogiq.ca/admin/keys)

## General Usage

In order to use the UrbanLogiq SDK, an API Key Context instance needs to be created. This context bundles together the region, environment, and API key information and will automatically sign requests.

### Specific usage: C++

Code using the C++ SDK will need to initialize the SDK first before any requests are used, for example:

```cpp
#include "ulsdk/ulsdk.h"
#include "ulsdk/api_key_context.h"

int main() {
    ul::init();
    ul::Key key = ul::Key(
	"00000000-0000-0000-0000-000000000000", // the user ID as displayed in the API key portal
	ul::Region::US, // the region of the API key
	std::string(std::getenv("UL_ACCESS_KEY")), // the access key
	std::string(std::getenv("UL_SECRET_KEY")) // the secret key
    );
    ul::ApiKeyContext context(key, ul::Environment::Prod);

    const auto result = ul::api::gate::bootstrap(&context);
}
```

## Supported Environments

### C++

The C++ SDK requires a C++17 compliant compiler. It is currently tested with GCC and Clang, targeting Unix-like environments. The SDK requires the following libraries to be installed:
* `libcurl` 7.81 or newer
* `arrow` 17.0.0 or newer
* `libsodium` 1.0.18 or newer
* `flatbuffers` 23.5.26

### Python

The Python SDK requires Python 3.12 or later. Dependencies listed in the `pyproject.toml` file are required.

### TypeScript

Support for TypeScript is currently in development.

### C# / .NET

Support for C# / .NET is currently in development.

### Java

Support for Java is currently in development.

### Rust

Support for Rust is currently in development.

## Reporting Issues

Please report all issues through the Github issue tracker. Pull requests will not be accepted for generated code; if there is an issue with generated components please report an issue and we will provide regenerated code with the necessary fix.
