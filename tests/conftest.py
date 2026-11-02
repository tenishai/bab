from __future__ import annotations

import pytest

from bab.catalogue import Catalogue
from bab.store import StoreError


class FakeStore:
    """Records tuples; answers check/list from them literally (no inheritance —
    the model's semantics are covered by `fga model test`, not here)."""

    def __init__(self, tuples=(), broken=False):
        self.tuples = set(tuples)
        self.broken = broken

    def _guard(self):
        if self.broken:
            raise StoreError("connection refused")

    def check(self, user, relation, object, context=None):
        self._guard()
        now = (context or {}).get("current_time")
        for t in self.tuples:
            if t.key != (user, relation, object):
                continue
            if t.expires_at is None:
                return True
            if now is None:
                raise StoreError("conditional tuple checked without current_time")
            if now < t.expires_at:
                return True
        return False

    def list_users(self, object, relation, user_type="user"):
        self._guard()
        return sorted(t.user for t in self.tuples
                      if t.object == object and t.relation == relation and t.user.startswith(user_type + ":"))

    def list_objects(self, user, relation, object_type):
        self._guard()
        return sorted(t.object for t in self.tuples
                      if t.user == user and t.relation == relation and t.object.startswith(object_type + ":"))

    def write(self, tuples):
        self.tuples |= set(tuples)

    def delete(self, tuples):
        self.tuples -= set(tuples)

    def read_all(self):
        self._guard()
        return sorted(self.tuples, key=str)


@pytest.fixture
def cat():
    return Catalogue.from_dict({
        "resources": ["project", "cluster", "namespace"],
        "actions": [
            {"name": "log_read", "tier": "read", "global": True},
            {"name": "pod_delete", "tier": "mutate"},
        ],
    })


class FakeDatadog:
    """Datadog's service-account application-key API, as the DatadogMinter's `http` function:
    records every call, hands out key ids, forgets a key on DELETE, 404s one already gone."""

    def __init__(self, refuse: str | None = None):
        self.calls: list[tuple[str, str, dict | None]] = []
        self.keys: dict[str, dict] = {}
        self.refuse = refuse  # an error sentence Datadog answers every create with
        self.last_headers: dict = {}
        self.n = 0

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, body))
        self.last_headers = dict(headers)
        _, _, key_id = url.rpartition("/application_keys/") if "/application_keys/" in url else (None, None, "")
        if method == "POST":
            if self.refuse:
                return 403, {"errors": [{"title": "Forbidden", "detail": self.refuse}]}
            self.n += 1
            kid = f"kid-{self.n}"
            attrs = body["data"]["attributes"]
            self.keys[kid] = {"name": attrs["name"], "scopes": list(attrs["scopes"])}
            return 201, {"data": {"type": "application_keys", "id": kid,
                                  "attributes": {**self.keys[kid], "key": f"secret-{kid}"}}}
        if method == "DELETE":
            return (204, {}) if self.keys.pop(key_id, None) is not None else (404, {"errors": ["Not found"]})
        return 405, {"errors": ["method"]}


class FakeGitHub:
    """GitHub's App API as the GitHubMinter's `http` function: the app, one installation,
    installation tokens that echo what they were narrowed to, a repository count."""

    def __init__(self, refuse: str | None = None, installation: str = "777"):
        self.calls: list[tuple[str, str, dict | None]] = []
        self.headers: list[dict] = []
        self.refuse = refuse
        self.installation = installation
        self.n = 0

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, body))
        self.headers.append(dict(headers))
        path = url.split("/", 3)[3] if url.count("/") >= 3 else ""
        if method == "GET" and path == "app":
            return 200, {"id": 4242, "slug": "acme-room"}
        if method == "GET" and path == f"app/installations/{self.installation}":
            return 200, {"id": int(self.installation), "app_slug": "acme-room", "account": {"login": "acme"}}
        if method == "GET" and path.startswith("app/installations/"):
            return 404, {"message": "Not Found"}
        if method == "POST" and path == f"app/installations/{self.installation}/access_tokens":
            if self.refuse:
                return 422, {"message": self.refuse}
            self.n += 1
            out = {"token": f"ghs-{self.n}", "expires_at": "2026-10-30T15:05:00Z", "permissions": body["permissions"]}
            if body.get("repositories"):
                out["repositories"] = [{"name": r} for r in body["repositories"]]
            return 201, out
        if method == "GET" and path.startswith("installation/repositories"):
            return 200, {"total_count": 3}
        return 405, {"message": "method"}


def fake_jwt(claims: dict) -> str:
    """An unsigned JWT with these claims: what the metadata server's identity endpoint answers."""
    import base64
    import json

    def b64(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")
    return f"{b64({'alg': 'RS256', 'typ': 'JWT'})}.{b64(claims)}.sig"


BAB_EMAIL = "bab-access@example-project.iam.gserviceaccount.com"


class FakeGoogle:
    """The metadata server, the IAM Credentials API and Resource Manager as the GcpMinter's
    `http` function: bab's own token and identity, impersonation that echoes the account it
    was asked for, projects bab may or may not read, a folder's projects over two pages."""

    def __init__(self, forbidden: tuple[str, ...] = ("locked-project",), refuse_impersonation: str | None = None,
                 vertex_forbidden: tuple[str, ...] = ("europe-west9",)):
        self.calls: list[tuple[str, str, dict | None]] = []
        self.headers: list[dict] = []
        self.forbidden = set(forbidden)
        self.vertex_forbidden = set(vertex_forbidden)
        self.refuse_impersonation = refuse_impersonation
        self.n = 0

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, body))
        self.headers.append(dict(headers))
        if url.startswith("http://metadata.google.internal/"):
            if headers.get("Metadata-Flavor") != "Google":
                return 403, {}
            path = url.split("/service-accounts/default/", 1)[1]
            if path.startswith("token"):
                self.n += 1
                return 200, {"access_token": f"own-{self.n}", "expires_in": 1800, "token_type": "Bearer"}
            if path.startswith("identity"):
                aud = url.split("audience=")[1].split("&")[0]
                return 200, {"text": fake_jwt({"sub": "1122334455", "email": BAB_EMAIL, "aud": aud, "iss": "https://accounts.google.com"})}
            if path.startswith("?recursive=true"):
                return 200, {"aliases": ["default"], "email": BAB_EMAIL, "scopes": ["https://www.googleapis.com/auth/cloud-platform"]}
            return 404, {}
        if ":generateAccessToken" in url:
            if self.refuse_impersonation:
                return 403, {"error": {"code": 403, "message": self.refuse_impersonation, "status": "PERMISSION_DENIED"}}
            sa = url.rsplit("/serviceAccounts/", 1)[1].split(":")[0]
            self.n += 1
            return 200, {"accessToken": f"imp-{self.n}-{sa}", "expireTime": "2026-11-01T13:00:00.123456Z"}
        if url.startswith("https://aiplatform.googleapis.com/v1beta1/publishers/"):
            # The global publisher-model listing, billed to the project in the header; two pages for google.
            if headers.get("x-goog-user-project") in self.forbidden:
                return 403, {"error": {"code": 403, "message": "Permission 'aiplatform.publisherModels.list' denied", "status": "PERMISSION_DENIED"}}
            publisher = url.split("/publishers/")[1].split("/")[0]
            if publisher == "google":
                if "pageToken=" in url:
                    return 200, {"publisherModels": VERTEX_GOOGLE_PAGE2}
                return 200, {"publisherModels": VERTEX_GOOGLE_PAGE1, "nextPageToken": "g-2"}
            if publisher == "anthropic":
                return 200, {"publisherModels": VERTEX_ANTHROPIC}
            return 200, {"publisherModels": []}
        if "aiplatform.googleapis.com/v1/projects/" in url and "/publishers/google/models" in url:
            location = url.split("/locations/")[1].split("/")[0]
            if location in self.vertex_forbidden:
                return 403, {"error": {"code": 403, "message": "Permission 'aiplatform.endpoints.predict' denied", "status": "PERMISSION_DENIED"}}
            return 200, {"publisherModels": [{"name": f"publishers/google/models/gemini@{location}"}]}
        if "/v1/projects/" in url:
            pid = url.rsplit("/", 1)[1]
            if pid in self.forbidden:
                return 403, {"error": {"code": 403, "message": "The caller does not have permission", "status": "PERMISSION_DENIED"}}
            return 200, {"projectId": pid, "projectNumber": "123456789012", "name": pid, "lifecycleState": "ACTIVE"}
        if "/v3/projects?parent=" in url:
            parent = url.split("parent=")[1].split("&")[0]
            if "pageToken=" in url:
                return 200, {"projects": [{"projectId": "old-project", "displayName": "Old", "state": "DELETE_REQUESTED", "parent": parent},
                                          {"projectId": "locked-project", "displayName": "Locked", "state": "ACTIVE", "parent": parent}]}
            return 200, {"projects": [{"projectId": "example-project", "displayName": "Example", "state": "ACTIVE", "parent": parent}],
                         "nextPageToken": "page-2"}
        return 405, {}


# ---- captured shapes for model discovery --------------------------------------------
# Vertex AI's publisher-model rows as the global v1beta1 endpoint lists them (name, versionId,
# launchStage, supportedActions); Bedrock's modelSummaries and inferenceProfileSummaries.
# Shapes are the vendors'; the rows are a representative cut, not today's full list.


def _vertex(publisher: str, name: str, stage: str, *actions: str, version: str = "001") -> dict:
    return {"name": f"publishers/{publisher}/models/{name}", "versionId": version, "launchStage": stage,
            "openSourceCategory": "PROPRIETARY",
            "supportedActions": {a: {} for a in actions}}


STUDIO, TUNE, NOTEBOOK, DEPLOY = "openGenerationAiStudio", "openPromptTuningPipeline", "openNotebook", "deploy"
VERTEX_GOOGLE_PAGE1 = [
    _vertex("google", "gemini-2.5-pro", "GA", STUDIO, TUNE),
    _vertex("google", "gemini-2.5-flash", "GA", STUDIO, TUNE),
    _vertex("google", "gemini-3-pro-preview", "PUBLIC_PREVIEW", STUDIO),  # the family has GA rows: dropped
    _vertex("google", "gemini-1.5-pro", "DEPRECATED", STUDIO),
    _vertex("google", "gemini-2.5-flash-preview-tts", "GA", STUDIO),  # speech
    _vertex("google", "text-embedding-005", "GA", NOTEBOOK),
    _vertex("google", "multimodalembedding", "GA", NOTEBOOK),
    _vertex("google", "imagen-4.0-generate-001", "GA", STUDIO),
    _vertex("google", "veo-3.0-generate-001", "GA", STUDIO),
    _vertex("google", "text-bison", "GA", STUDIO),
    _vertex("google", "gemma-3-27b-it", "GA", DEPLOY, NOTEBOOK),  # deploy-only: not a model the room can call
]
VERTEX_GOOGLE_PAGE2 = [
    _vertex("google", "gemini-2.0-flash-001", "GA", STUDIO, TUNE),
    _vertex("google", "gemini-2.5-pro", "GA", STUDIO),  # listed twice across pages: once in the answer
    _vertex("google", "learnlm-2.0-flash-experimental", "EXPERIMENTAL", STUDIO),
]
VERTEX_ANTHROPIC = [
    _vertex("anthropic", "claude-sonnet-4-6", "GA", STUDIO),
    _vertex("anthropic", "claude-opus-4-1", "GA", STUDIO),
    _vertex("anthropic", "claude-3-5-sonnet-v2", "GA", STUDIO),
    _vertex("anthropic", "claude-haiku-4-5-preview", "PUBLIC_PREVIEW", STUDIO),
]


def _bedrock(model_id: str, name: str, provider: str, *kinds: str, outputs=("TEXT",), status="ACTIVE") -> dict:
    return {"modelArn": f"arn:aws:bedrock:us-east-1::foundation-model/{model_id}", "modelId": model_id,
            "modelName": name, "providerName": provider, "inputModalities": ["TEXT"],
            "outputModalities": list(outputs), "responseStreamingSupported": True,
            "customizationsSupported": [], "inferenceTypesSupported": list(kinds),
            "modelLifecycle": {"status": status}}


def _profile(pid: str, *model_ids: str, kind="SYSTEM_DEFINED", status="ACTIVE") -> dict:
    return {"inferenceProfileId": pid, "inferenceProfileName": pid, "type": kind, "status": status,
            "inferenceProfileArn": f"arn:aws:bedrock:us-east-1:123456789012:inference-profile/{pid}",
            "models": [{"modelArn": f"arn:aws:bedrock:{r}::foundation-model/{m}"}
                       for m in model_ids for r in ("us-east-1", "us-west-2")]}


BEDROCK_MODELS = [
    _bedrock("anthropic.claude-sonnet-4-5-20250929-v1:0", "Claude Sonnet 4.5", "Anthropic", "INFERENCE_PROFILE"),
    _bedrock("anthropic.claude-3-haiku-20240307-v1:0", "Claude 3 Haiku", "Anthropic", "ON_DEMAND", "INFERENCE_PROFILE"),
    _bedrock("anthropic.claude-3-5-sonnet-20240620-v1:0:200k", "Claude 3.5 Sonnet", "Anthropic", "PROVISIONED"),
    _bedrock("anthropic.claude-v2", "Claude", "Anthropic", "ON_DEMAND", status="LEGACY"),
    _bedrock("amazon.nova-pro-v1:0", "Nova Pro", "Amazon", "INFERENCE_PROFILE"),
    _bedrock("amazon.nova-canvas-v1:0", "Nova Canvas", "Amazon", "ON_DEMAND", outputs=("IMAGE",)),
    _bedrock("amazon.nova-sonic-v1:0", "Nova Sonic", "Amazon", "ON_DEMAND", outputs=("SPEECH", "TEXT")),
    _bedrock("amazon.titan-embed-text-v2:0", "Titan Text Embeddings V2", "Amazon", "ON_DEMAND", outputs=("EMBEDDING",)),
    _bedrock("amazon.titan-text-express-v1", "Titan Text G1 - Express", "Amazon", "ON_DEMAND"),
    _bedrock("cohere.rerank-v3-5:0", "Rerank 3.5", "Cohere", "ON_DEMAND"),
    _bedrock("meta.llama3-3-70b-instruct-v1:0", "Llama 3.3 70B Instruct", "Meta", "INFERENCE_PROFILE"),  # no profile here
    _bedrock("deepseek.r1-v1:0", "DeepSeek-R1", "DeepSeek", "INFERENCE_PROFILE"),
    _bedrock("mistral.pixtral-large-2502-v1:0", "Pixtral Large (25.02)", "Mistral AI", "INFERENCE_PROFILE"),
]
BEDROCK_PROFILES = [
    _profile("us.anthropic.claude-sonnet-4-5-20250929-v1:0", "anthropic.claude-sonnet-4-5-20250929-v1:0"),
    _profile("global.anthropic.claude-sonnet-4-5-20250929-v1:0", "anthropic.claude-sonnet-4-5-20250929-v1:0"),
    _profile("eu.anthropic.claude-sonnet-4-5-20250929-v1:0", "anthropic.claude-sonnet-4-5-20250929-v1:0"),
    _profile("us.anthropic.claude-3-haiku-20240307-v1:0", "anthropic.claude-3-haiku-20240307-v1:0"),
    _profile("us.amazon.nova-pro-v1:0", "amazon.nova-pro-v1:0"),
    _profile("us.deepseek.r1-v1:0", "deepseek.r1-v1:0"),
    _profile("global.mistral.pixtral-large-2502-v1:0", "mistral.pixtral-large-2502-v1:0"),
    _profile("my-app-profile", "amazon.nova-pro-v1:0", kind="APPLICATION"),
]
