import ballerina/http;
import ballerina/mcp;
import ballerina/test;

// An HTTPS OpenID Provider shaped like one that supports token exchange without advertising it: its issuer
// has a path, so discovery tries two locations before the one it serves, and `grant_types_supported` omits
// the token exchange grant unless a test asks for it.
const MOCK_EXCHANGE_IDP_ORIGIN = "https://localhost:18091";
const MOCK_EXCHANGE_IDP_ISSUER = MOCK_EXCHANGE_IDP_ORIGIN + "/oauth/v2/oauth-anonymous";
const MOCK_EXCHANGE_TOKEN_ENDPOINT = MOCK_EXCHANGE_IDP_ORIGIN + "/oauth/v2/oauth-token";
const MOCK_EXCHANGE_ID_TOKEN = "mock-id-token-value";
const MOCK_EXCHANGE_SECRET = "mock-exchange-secret";

isolated boolean mockAdvertisesTokenExchange = false;
// The form and Authorization header of each token request.
isolated [map<string>, string][] mockExchangeRequests = [];

final string mockExchangeIdJag = unsignedJwt({iss: MOCK_EXCHANGE_IDP_ISSUER, aud: "https://as.example",
    client_id: "mcp-client", 'resource: "https://mcp.example/mcp", scope: "todos.read"});

listener http:Listener mockExchangeIdentityProviderListener = new (18091, secureSocket = {
    key: {
        certFile: MTLS_TEST_RESOURCES + "cimd-mtls-certificate.pem",
        keyFile: MTLS_TEST_RESOURCES + "cimd-mtls-private-key.pem"
    }
});

service /oauth/v2 on mockExchangeIdentityProviderListener {
    resource function get oauth\-anonymous/\.well\-known/openid\-configuration() returns json {
        boolean advertises;
        lock {
            advertises = mockAdvertisesTokenExchange;
        }
        string[] grantTypes = ["authorization_code", "refresh_token"];
        if advertises {
            grantTypes.push("urn:ietf:params:oauth:grant-type:token-exchange");
        }
        return {
            issuer: MOCK_EXCHANGE_IDP_ISSUER,
            authorization_endpoint: MOCK_EXCHANGE_IDP_ORIGIN + "/oauth/v2/oauth-authorize",
            token_endpoint: MOCK_EXCHANGE_TOKEN_ENDPOINT,
            grant_types_supported: grantTypes,
            token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"]
        };
    }

    resource function post oauth\-token(http:Request request) returns http:Ok|http:BadRequest|error {
        map<string> form = check request.getFormParams();
        string|http:HeaderNotFoundError authorization = request.getHeader("Authorization");
        lock {
            mockExchangeRequests.push([form.clone(), authorization is string ? authorization : ""]);
        }
        if form["grant_type"] != "urn:ietf:params:oauth:grant-type:token-exchange" ||
                form["subject_token"] != MOCK_EXCHANGE_ID_TOKEN {
            return <http:BadRequest>{body: {'error: "invalid_grant", error_description: "Unknown subject token"}};
        }
        return <http:Ok>{
            body: {
                access_token: mockExchangeIdJag,
                issued_token_type: "urn:ietf:params:oauth:token-type:id-jag",
                token_type: "N_A",
                expires_in: 300
            }
        };
    }
}

// The metadata locations the issuer path does not serve, with a fixed body so runs record the same events.
service /\.well\-known on mockExchangeIdentityProviderListener {
    resource function get [string... path]() returns http:NotFound => {body: {'error: "not_found"}};
}

final readonly & mcp:IdentityAssertionContext mockExchangeContext = {
    audience: "https://as.example",
    'resource: "https://mcp.example/mcp",
    clientId: "mcp-client",
    scopes: ["todos.read"]
};

function mockExchangeIdentityProvider(mcp:ClientSecretAuthMethod authMethod) returns mcp:IdentityProviderConfig => {
    issuer: MOCK_EXCHANGE_IDP_ISSUER,
    clientId: "idp-client",
    clientAuth: {clientSecret: MOCK_EXCHANGE_SECRET, authMethod},
    // The test certificate does not name localhost.
    secureSocket: {cert: MTLS_TEST_RESOURCES + "cimd-mtls-certificate.pem", verifyHostName: false}
};

function setMockAdvertisesTokenExchange(boolean advertises) {
    lock {
        mockAdvertisesTokenExchange = advertises;
    }
}

function lastMockExchangeRequest() returns [map<string>, string] {
    lock {
        return mockExchangeRequests[mockExchangeRequests.length() - 1].clone();
    }
}

function recordedEvents(string connectionId) returns readonly & InspectorEvent[] {
    readonly & InspectorEvent[] events = eventStore.after(connectionId, 0) ?: [];
    eventStore.remove(connectionId);
    return events;
}

@test:Config {}
function testIdJagExchangeWithoutAdvertisedGrant() returns error? {
    setMockAdvertisesTokenExchange(false);
    string connectionId = "ema-unadvertised-exchange";
    eventStore.open(connectionId);

    // The helper rejects the provider before sending the exchange.
    string|error rejected = mcp:exchangeIdTokenForIdJag(MOCK_EXCHANGE_ID_TOKEN, mockExchangeContext,
        mockExchangeIdentityProvider(mcp:CLIENT_SECRET_POST));
    test:assertTrue(rejected is error);
    if rejected is error {
        test:assertTrue(rejected.message().includes("does not include the token exchange grant"));
    }

    string idJag = check exchangeIdTokenForIdJag(MOCK_EXCHANGE_ID_TOKEN, mockExchangeContext,
        mockExchangeIdentityProvider(mcp:CLIENT_SECRET_POST), new InspectorClientObserver(connectionId));
    test:assertEquals(idJag, mockExchangeIdJag);

    [map<string>, string] [form, authorization] = lastMockExchangeRequest();
    test:assertEquals(form, {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "requested_token_type": "urn:ietf:params:oauth:token-type:id-jag",
        "subject_token": MOCK_EXCHANGE_ID_TOKEN,
        "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
        "audience": "https://as.example",
        "resource": "https://mcp.example/mcp",
        "scope": "todos.read",
        "client_id": "idp-client",
        "client_secret": MOCK_EXCHANGE_SECRET
    });
    test:assertEquals(authorization, "");

    readonly & InspectorEvent[] events = recordedEvents(connectionId);
    // No credential or token reaches the transcript.
    string transcript = events.toJsonString();
    test:assertFalse(transcript.includes(MOCK_EXCHANGE_ID_TOKEN));
    test:assertFalse(transcript.includes(MOCK_EXCHANGE_SECRET));
    test:assertFalse(transcript.includes(mockExchangeIdJag));

    // Discovery tries the two locations the issuer path doesn't serve, then reads the third.
    string[] summary = from InspectorEvent event in events
        select string `${event.eventType} ${event.httpMethod ?: "-"} ${event.eventUrl ?: "-"} ${event.statusCode ?: 0}`;
    string wellKnownAs = MOCK_EXCHANGE_IDP_ORIGIN + "/.well-known/oauth-authorization-server/oauth/v2/oauth-anonymous";
    string wellKnownOidc = MOCK_EXCHANGE_IDP_ORIGIN + "/.well-known/openid-configuration/oauth/v2/oauth-anonymous";
    string metadataUrl = MOCK_EXCHANGE_IDP_ISSUER + "/.well-known/openid-configuration";
    test:assertEquals(summary, [
        string `http.request GET ${wellKnownAs} 0`,
        string `http.response GET ${wellKnownAs} 404`,
        string `http.body GET ${wellKnownAs} 404`,
        string `http.request GET ${wellKnownOidc} 0`,
        string `http.response GET ${wellKnownOidc} 404`,
        string `http.body GET ${wellKnownOidc} 404`,
        string `http.request GET ${metadataUrl} 0`,
        string `http.response GET ${metadataUrl} 200`,
        string `http.body GET ${metadataUrl} 200`,
        string `http.request POST ${MOCK_EXCHANGE_TOKEN_ENDPOINT} 0`,
        string `http.response POST ${MOCK_EXCHANGE_TOKEN_ENDPOINT} 200`,
        string `http.body POST ${MOCK_EXCHANGE_TOKEN_ENDPOINT} 200`,
        string `oauth.token_acquired - ${MOCK_EXCHANGE_TOKEN_ENDPOINT} 0`
    ]);
    foreach InspectorEvent event in events {
        test:assertEquals(event.eventTarget, "identity_provider");
    }

    InspectorEvent request = events[9];
    test:assertEquals(request.eventMessage, "OAuth token request");
    test:assertEquals(request.eventHeaders, {
        "content-type": "application/x-www-form-urlencoded",
        "accept": "application/json"
    });
    test:assertEquals(request.eventBody,
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange" +
        "&requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aid-jag" +
        "&subject_token=[REDACTED]" +
        "&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aid_token" +
        "&audience=https%3A%2F%2Fas.example&resource=https%3A%2F%2Fmcp.example%2Fmcp&scope=todos.read" +
        "&client_id=idp-client&client_secret=[REDACTED]");

    InspectorEvent response = events[11];
    test:assertEquals(response.eventMessage, "OAuth token response, tokens redacted");
    test:assertEquals(check (response.eventBody ?: "").fromJsonString(), {
        access_token: "[REDACTED]",
        issued_token_type: "urn:ietf:params:oauth:token-type:id-jag",
        token_type: "N_A",
        expires_in: 300
    });
    test:assertEquals(events[12].eventMessage, "ID-JAG issued by the Identity Provider");
}

@test:Config {}
function testIdJagExchangeWithClientSecretBasic() returns error? {
    setMockAdvertisesTokenExchange(false);
    string connectionId = "ema-exchange-basic";
    eventStore.open(connectionId);
    _ = check exchangeIdTokenForIdJag(MOCK_EXCHANGE_ID_TOKEN, mockExchangeContext,
        mockExchangeIdentityProvider(mcp:CLIENT_SECRET_BASIC), new InspectorClientObserver(connectionId));

    [map<string>, string] [form, authorization] = lastMockExchangeRequest();
    test:assertFalse(form.hasKey("client_id"));
    test:assertFalse(form.hasKey("client_secret"));
    test:assertEquals(authorization, "Basic " + string `idp-client:${MOCK_EXCHANGE_SECRET}`.toBytes().toBase64());

    readonly & InspectorEvent[] events = recordedEvents(connectionId);
    InspectorEvent[] requests = from InspectorEvent event in events
        where event.eventType == "http.request" && event.httpMethod == "POST"
        select event;
    test:assertEquals(requests.length(), 1);
    test:assertEquals(requests[0].eventHeaders["Authorization"], ["[REDACTED]"]);
    test:assertFalse(events.toJsonString().includes(authorization));
}

@test:Config {}
function testIdJagExchangeRejectsUnexpectedResponses() returns error? {
    setMockAdvertisesTokenExchange(false);
    string connectionId = "ema-exchange-rejected";
    eventStore.open(connectionId);
    string|error result = exchangeIdTokenForIdJag("another-id-token", mockExchangeContext,
        mockExchangeIdentityProvider(mcp:CLIENT_SECRET_POST), new InspectorClientObserver(connectionId));
    test:assertTrue(result is error);
    if result is error {
        test:assertEquals(result.message(), string `Token endpoint '${MOCK_EXCHANGE_TOKEN_ENDPOINT}' rejected ` +
            "the request with 'invalid_grant': Unknown subject token.");
    }
    // The error response is recorded as the helper records it.
    InspectorEvent[] bodies = from InspectorEvent event in recordedEvents(connectionId)
        where event.eventType == "http.body" && event.httpMethod == "POST"
        select event;
    test:assertEquals(bodies.length(), 1);
    test:assertEquals(bodies[0].statusCode, 400);
    test:assertEquals(check (bodies[0].eventBody ?: "").fromJsonString(),
        {'error: "invalid_grant", error_description: "Unknown subject token"});

    test:assertEquals(parseTokenExchangeResponse({access_token: "x", issued_token_type: TOKEN_TYPE_ID_TOKEN,
        token_type: "N_A"}, TOKEN_TYPE_ID_JAG, "https://idp.example/token") is error, true);
    test:assertEquals(parseTokenExchangeResponse({access_token: "x", issued_token_type: TOKEN_TYPE_ID_JAG,
        token_type: "Bearer"}, TOKEN_TYPE_ID_JAG, "https://idp.example/token") is error, true);

    // The ID-JAG token type check is kept.
    test:assertTrue(validateIdJagIssuanceSupported({issuer: "https://idp.example", token_endpoint: "https://idp.example/t",
        identity_chaining_requested_token_types_supported: [TOKEN_TYPE_ID_TOKEN]}) is error);
    // So is the client authentication check, while the advertised grant types are not consulted.
    test:assertTrue(validateTokenExchangeSupported({clientSecret: "s", authMethod: mcp:CLIENT_SECRET_BASIC},
        {issuer: "https://idp.example", token_endpoint: "https://idp.example/t",
        token_endpoint_auth_methods_supported: ["private_key_jwt"]}) is error);
    test:assertEquals(validateTokenExchangeSupported((), {issuer: "https://idp.example",
        token_endpoint: "https://idp.example/t", grant_types_supported: ["authorization_code"]}), ());
}

// Where the provider advertises the grant, the helper and the playground's exchange record the same events.
@test:Config {}
function testIdJagExchangeEventsMatchTheHelper() returns error? {
    setMockAdvertisesTokenExchange(true);
    string helperConnection = "ema-exchange-helper";
    string playgroundConnection = "ema-exchange-playground";
    eventStore.open(helperConnection);
    eventStore.open(playgroundConnection);
    string helperIdJag = check mcp:exchangeIdTokenForIdJag(MOCK_EXCHANGE_ID_TOKEN, mockExchangeContext,
        mockExchangeIdentityProvider(mcp:CLIENT_SECRET_POST), new InspectorClientObserver(helperConnection));
    [map<string>, string] helperRequest = lastMockExchangeRequest();
    string playgroundIdJag = check exchangeIdTokenForIdJag(MOCK_EXCHANGE_ID_TOKEN, mockExchangeContext,
        mockExchangeIdentityProvider(mcp:CLIENT_SECRET_POST), new InspectorClientObserver(playgroundConnection));
    [map<string>, string] playgroundRequest = lastMockExchangeRequest();
    setMockAdvertisesTokenExchange(false);

    test:assertEquals(playgroundIdJag, helperIdJag);
    test:assertEquals(playgroundRequest, helperRequest);
    readonly & InspectorEvent[] helperEvents = recordedEvents(helperConnection);
    readonly & InspectorEvent[] playgroundEvents = recordedEvents(playgroundConnection);
    test:assertEquals(playgroundEvents.length(), helperEvents.length());
    foreach int i in 0 ..< helperEvents.length() {
        test:assertEquals(comparableEvent(playgroundEvents[i]), comparableEvent(helperEvents[i]));
    }
}

// An event without the fields that differ between runs: its sequence, time, connection, and the values of
// response headers such as `date`.
function comparableEvent(InspectorEvent event) returns map<anydata> => {
    eventType: event.eventType,
    eventTarget: event.eventTarget,
    eventUrl: event.eventUrl,
    httpMethod: event.httpMethod,
    statusCode: event.statusCode,
    eventHeaders: event.eventType == "http.response" ? event.eventHeaders.keys() : event.eventHeaders,
    eventBody: event.eventBody,
    eventMessage: event.eventMessage
};
