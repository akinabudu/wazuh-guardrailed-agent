import warnings

from langchain_core._api.deprecation import LangChainPendingDeprecationWarning


def configure_langgraph_warnings() -> None:
    warnings.filterwarnings(
        "ignore",
        message=r"The default value of `allowed_objects` will change.*",
        category=LangChainPendingDeprecationWarning,
    )
