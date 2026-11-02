"""Model discovery: the chat models a connected cloud offers, cut down to what a room would
show in New agent (chat text models, generally available). The vendor calls live on the
minters (`GcpMinter.list_models`, `AwsMinter.list_models`); everything here is a pure
function over the vendor's own answer, so the filters are tested on captured shapes.

A row is `{"id", "label", "publisher", "family", "stage", "via"}`: `id` is what the room
hands the provider (a bare Vertex publisher model name, a Bedrock model id or system
inference profile id), `family` a best-effort grouping from the name (claude, gemini,
llama, nova, ...), `stage` the vendor's launch stage, `via` how Bedrock serves it
(`on-demand` or `inference-profile`; Vertex rows carry null).
"""

from __future__ import annotations

import re

VERTEX_API = "https://aiplatform.googleapis.com/v1beta1"
VERTEX_PUBLISHERS = ("google", "anthropic")
VERTEX_PAGE_SIZE = 200
PROVIDER_FOR = {"gcp": "vertex_ai", "aws": "bedrock"}  # vendor -> the provider name a room's catalogue uses

# Vertex launch stages: GA rows always; PUBLIC_PREVIEW only when a family has nothing GA.
GA, PUBLIC_PREVIEW = "GA", "PUBLIC_PREVIEW"
# A supportedActions key that means "this model answers a generate call" (Vertex AI Studio
# opens it). Models that only deploy, tune or open a notebook are not chat models the room can call.
_VERTEX_GENERATE_ACTION = re.compile(r"generation|genie", re.IGNORECASE)

# Names that are not chat text models on either cloud: embeddings, image, video, speech and
# the retired PaLM-era families. Matched as whole name segments (split on - . _ : @ /) ...
_NOT_CHAT_TOKENS = frozenset({
    "tts", "gecko", "bison", "codey", "veo", "image", "video", "audio", "lyria", "chirp", "canvas",
    "reel", "sonic", "live", "ocr", "speech", "stable", "voyage", "vision", "music",
})
# ... or anywhere in the name, where the vendor glues words together (multimodalembedding, imagen).
_NOT_CHAT_SUBSTRINGS = ("embed", "imagen", "rerank")
_SPLIT = re.compile(r"[-._:@/]")

_PUBLISHER_LABEL = {
    "google": "Google", "anthropic": "Anthropic", "meta": "Meta", "mistralai": "Mistral AI",
    "ai21": "AI21 Labs", "cohere": "Cohere", "deepseek-ai": "DeepSeek", "openai": "OpenAI", "qwen": "Qwen",
}
_ACRONYMS = {"gpt": "GPT", "oss": "OSS", "ai": "AI", "it": "IT", "er": "ER", "r1": "R1"}


def is_chat_name(name: str) -> bool:
    """False for a model whose name says it is not a chat text model."""
    low = name.lower()
    if any(s in low for s in _NOT_CHAT_SUBSTRINGS):
        return False
    return not any(t in _NOT_CHAT_TOKENS for t in _SPLIT.split(low))


def family_of(name: str) -> str:
    """The model's family from its bare name: the leading run of letters (`claude-sonnet-4-6`
    -> claude, `gemini-2.5-pro` -> gemini, `llama3-3-70b` -> llama). A run shorter than three
    letters names nothing (`r1`), and the caller falls back to the publisher."""
    m = re.match(r"[a-z]+", name.lower())
    word = m.group(0) if m else ""
    return word if len(word) >= 3 else ""


def label_for(name: str) -> str:
    """A readable name from a bare model name: `claude-sonnet-4-6` -> "Claude Sonnet 4.6",
    `gemini-2.5-pro` -> "Gemini 2.5 Pro", `claude-3-5-sonnet-v2` -> "Claude 3.5 Sonnet v2",
    `llama-3-3-70b-instruct` -> "Llama 3.3 70B Instruct". Best effort, never the vendor's truth."""
    words: list[str] = []
    for tok in [t for t in re.split(r"[-_]", name) if t]:
        low = tok.lower()
        if low.isdigit() and words and words[-1].replace(".", "").isdigit():
            words[-1] = f"{words[-1]}.{low}"
        elif low.isdigit() or re.fullmatch(r"\d+(\.\d+)?", low):
            words.append(low)
        elif re.fullmatch(r"\d+[bBkKmM]", low):
            words.append(low.upper())
        elif re.fullmatch(r"v\d+", low):
            words.append(low)
        elif low in _ACRONYMS:
            words.append(_ACRONYMS[low])
        else:
            words.append(low[:1].upper() + low[1:])
    return " ".join(words)


def publisher_label(segment: str) -> str:
    return _PUBLISHER_LABEL.get(segment.lower(), segment.replace("-", " ").title())


def vertex_publisher_models_url(publisher: str, page_token: str = "") -> str:
    """Vertex AI's publisher-model listing. Only the global endpoint lists them (the regional
    hosts answer an empty list); the project rides in the `x-goog-user-project` header. Built
    here, never taken from a caller: bab presents its own token to it."""
    return (f"{VERTEX_API}/publishers/{publisher}/models?pageSize={VERTEX_PAGE_SIZE}"
            + (f"&pageToken={page_token}" if page_token else ""))


def vertex_models(listed: list[tuple[str, dict]]) -> list[dict]:
    """The room's rows from Vertex's publisher models, `(publisher, publisherModel)` pairs as
    listed. Kept: a chat text name, a generate-type action in `supportedActions`, launch stage
    GA, or PUBLIC_PREVIEW when the family has nothing GA. Deprecated, private-preview and
    experimental rows go. `id` is the bare name; `via` is null (Vertex has one lane)."""
    rows: list[dict] = []
    for publisher, m in listed:
        name = str(m.get("name") or "").rsplit("/", 1)[-1]
        if not name or not is_chat_name(name):
            continue
        actions = m.get("supportedActions") or {}
        if not isinstance(actions, dict) or not any(_VERTEX_GENERATE_ACTION.search(k) for k in actions):
            continue
        stage = str(m.get("launchStage") or "")
        if stage not in (GA, PUBLIC_PREVIEW):
            continue
        rows.append({"id": name, "label": label_for(name), "publisher": publisher_label(publisher),
                     "family": family_of(name) or publisher.lower(), "stage": stage, "via": None})
    ga_families = {r["family"] for r in rows if r["stage"] == GA}
    kept = [r for r in rows if r["stage"] == GA or r["family"] not in ga_families]
    seen: set[str] = set()
    out = [r for r in kept if not (r["id"] in seen or seen.add(r["id"]))]
    return sorted(out, key=lambda r: (r["publisher"].lower(), r["family"], r["id"]))


# ---- Bedrock ---------------------------------------------------------------------

ON_DEMAND, INFERENCE_PROFILE = "on-demand", "inference-profile"
_NOT_TEXT_OUTPUT = frozenset({"IMAGE", "VIDEO", "EMBEDDING", "SPEECH", "AUDIO"})
_GEO = {"us": "us", "eu": "eu", "ap": "apac", "ca": "ca", "sa": "sa", "me": "me", "af": "af", "il": "il"}


def bedrock_family(model_id: str) -> str:
    """`anthropic.claude-sonnet-4-5-...` -> claude, `amazon.nova-pro-v1:0` -> nova,
    `meta.llama3-3-70b-...` -> llama, `deepseek.r1-v1:0` -> deepseek (the name says nothing)."""
    provider, _, rest = model_id.partition(".")
    return family_of(rest) or provider.lower() or rest


def profile_for(model_id: str, profiles: list[dict], region: str) -> str | None:
    """The system inference profile that routes `model_id`: `<geo>.<modelId>` for the
    region's geography (us, eu, apac), else `global.<modelId>`, else any that ends in the
    model id. None when Bedrock lists no profile for it."""
    want = {str(p.get("inferenceProfileId") or "") for p in profiles
            if p.get("type") in (None, "SYSTEM_DEFINED") and p.get("status") in (None, "ACTIVE")}
    want = {pid for pid in want if pid.endswith("." + model_id)}
    if not want:
        return None
    geo = _GEO.get(region.split("-")[0], region.split("-")[0])
    for pid in (f"{geo}.{model_id}", f"global.{model_id}"):
        if pid in want:
            return pid
    return min(want)


def bedrock_models(models: list[dict], profiles: list[dict], region: str) -> list[dict]:
    """The room's rows from `ListFoundationModels` (`modelSummaries`) and `ListInferenceProfiles`
    (`inferenceProfileSummaries`). Kept: output TEXT and nothing else, lifecycle ACTIVE, a chat
    text name, served ON_DEMAND (`id` = the model id, `via` on-demand) or, failing that, by a
    system inference profile (`id` = the profile id, `via` inference-profile); a profile-only
    model with no profile in the region is dropped, as is a provisioned-only one. Bedrock has
    no launch stage; an ACTIVE row is `stage` GA."""
    out: list[dict] = []
    for m in models:
        model_id = str(m.get("modelId") or "")
        outputs = set(m.get("outputModalities") or [])
        if not model_id or "TEXT" not in outputs or outputs & _NOT_TEXT_OUTPUT:
            continue
        if str((m.get("modelLifecycle") or {}).get("status") or "ACTIVE") != "ACTIVE":
            continue
        if not is_chat_name(model_id.partition(".")[2] or model_id):
            continue
        kinds = set(m.get("inferenceTypesSupported") or [])
        if "ON_DEMAND" in kinds:
            row_id, via = model_id, ON_DEMAND
        elif "INFERENCE_PROFILE" in kinds:
            pid = profile_for(model_id, profiles, region)
            if not pid:
                continue
            row_id, via = pid, INFERENCE_PROFILE
        else:
            continue
        bare = model_id.partition(".")[2].split(":")[0]
        out.append({"id": row_id, "label": str(m.get("modelName") or label_for(bare)),
                    "publisher": str(m.get("providerName") or publisher_label(model_id.partition(".")[0])),
                    "family": bedrock_family(model_id), "stage": GA, "via": via})
    return sorted(out, key=lambda r: (r["publisher"].lower(), r["family"], r["id"]))
