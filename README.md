# UrbanLogiq SDK

## Authentication

All access to UrbanLogiq systems requires some sort of authentication, typically with signed requests using API keys.

The API keys contain a Secret Key and an Access Key ID. The Secret Key is used to sign the requests and must be kept secret. Please do not deploy API keys in plain text to user applications or public repositories.

API keys can be managed through our API key portal:
* [US environments](https://home.urbanlogiq.us/admin/keys)
* [Canadian environments](https://home.urbanlogiq.ca/admin/keys)

To verify the keys are setup properly, you can call the `bootstrap` API, which returns basic user information. Please see the example sections below for how to call the `bootstrap` API.

## General Usage

In order to use the UrbanLogiq SDK, an API Key Context instance needs to be created. This context bundles together the region, environment, and API key information and will automatically sign requests.

The UrbanLogiq SDK is a single package containing multiple language implementations. These implementations do have several common packages (namespaces, etc., depending on language terminology) into which the code is grouped:
* A top level package that contains the plumbing and infrastructure needed to use the API. This includes the code for managing request signing keys, for signing and making requests, etc.
* A `types` package that contains automatically generated type definitions, serializers, and deserializers for many of the API endpoints.
* An `api` package that manages the calls to and from the API endpoints.

### Example: C++

Code using the C++ SDK will need to initialize the SDK first by calling `ul::init()` before any requests are used, for example:

```cpp
#include "ulsdk/ulsdk.h"
#include "ulsdk/api_key_context.h"

int main() {
    ul::init();
    ul::Key key = ul::Key(
	"00000000-0000-0000-0000-000000000000", // the user ID as displayed in the API key portal
	ul::Region::US, // the region of the API keyk
	std::string(std::getenv("UL_ACCESS_KEY")), // the access key
	std::string(std::getenv("UL_SECRET_KEY")) // the secret key
    );
    ul::ApiKeyContext ctx(key, ul::Environment::Prod);

    const auto result = ul::api::gate::bootstrap(&ctx);
}
```

### Example: Python

```python
import os
from ulsdk.api_key_context import ApiKeyContext
from ulsdk.keys import Key as SigningKey, Region, Environment
from ulsdk.api.gate import bootstrap

key = SigningKey(
    UUID("00000000-0000-0000-0000-000000000000"), # the user ID as displayed in the API key portal
    Region.US,
    os.environ("UL_ACCESS_KEY"), # the access key
    os.environ("UL_SECRET_KEY"), # the secret key
)
ctx = ApiKeyContext(key, Environment.Prod);
result = bootstrap(ctx)
```

### Example: Rust

```rust

use ulsdk::keys::Key;
use ulsdk::request_context::ApiKeyContext;
use ulsdk::api::gate::bootstrap;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let key = Key::try_new(
	Uuid::from_str("00000000-0000-0000-0000-000000000000")?, // the user ID as displayed in the API key portal
	Region::US,
	std::env::var("UL_ACCESS_KEY")?,
	std::env::var("UL_SECRET_KEY")?,
    )?;
    let ctx = ApiKeyContext::new(key, Environment::Prod);
    let result = bootstrap(&ctx).await;

    Ok(())
}
```

### Example: Java

```java
import com.urbanlogiq.ulsdk.Environment;
import com.urbanlogiq.ulsdk.Key;
import com.urbanlogiq.ulsdk.Region;
import com.urbanlogiq.ulsdk.ApiKeyContext;
import com.urbanlogiq.ulsdk.api.gate.Bootstrap;
import com.urbanlogiq.ulsdk.api.gate.Gate;

class Test {
    public static void Main(String[] args) {
	Key key = new Key(
	    UUID.fromString("00000000-0000-0000-0000-000000000000")?, // the user ID as displayed in the API key portal
	    Region.CA,
	    System.getenv("UL_ACCESS_KEY"),
	    System.getenv("UL_SECRET_KEY"),
	);
	ApiKeyContext ctx = new ApiKeyContext(key, Environment.Prod);
	Bootstrap result = Gate.bootstrap(ctx);
    }
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

### Rust

The Rust SDK has no known minimum version requirement, however we test it with Rust 1.86.

### Java

The Java SDK is tested with JDK 17 and has been verified with later versions.

### Other languages

Support for other languages is currently being worked on.

## Reporting Issues

Please report all issues through the Github issue tracker. Pull requests will not be accepted for generated code; if there is an issue with generated components please report an issue and we will provide regenerated code with the necessary fix.
