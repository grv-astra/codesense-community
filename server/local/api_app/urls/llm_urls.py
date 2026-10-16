from django.urls import path

from ..views.llm_views import LLMSettingsView, LLMStatusView, LLMTestView

urlpatterns = [
    path("settings/llm/", LLMSettingsView.as_view(), name="llm-settings"),
    path("settings/llm/test/", LLMTestView.as_view(), name="llm-settings-test"),
    path("llm/status/", LLMStatusView.as_view(), name="llm-status"),
]
