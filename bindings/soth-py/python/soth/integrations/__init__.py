"""Framework integrations.

Where `soth.instrumentation` monkey-patches provider SDKs directly,
this package targets *frameworks* that abstract over multiple
providers — LangChain, LlamaIndex, LiteLLM. Each integration plugs
into the framework's native callback / middleware system so SOTH
participates in the framework's existing lifecycle rather than
intercepting at the HTTP layer.

The integrations are imported lazily via attribute access so
`import soth` doesn't pull in LangChain etc. unless the customer
asks for them.

Usage:
    # LangChain
    from soth.integrations.langchain import SothCallbackHandler
    chain.invoke({...}, config={"callbacks": [SothCallbackHandler()]})

    # LlamaIndex
    from soth.integrations.llamaindex import SothEventHandler
    Settings.callback_manager = CallbackManager([SothEventHandler()])

    # LiteLLM
    from soth.integrations.litellm import register_callbacks
    register_callbacks()  # adds soth to litellm.callbacks
"""

from __future__ import annotations

# Sub-modules import-on-demand. Each one tolerates its underlying
# framework not being installed — returns helpful "feature unavailable"
# error if the customer tries to use it.

__all__ = [
    "langchain",
    "llamaindex",
    "litellm",
]
