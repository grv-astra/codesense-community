"""Bring-your-own LLM verification.

Lets any edition -- Community included -- verify findings through an LLM the
user already has. This package ships in the Community export, so it must NEVER
import the llm_analysis-gated bundled-model subsystem (scanner.rag.llm,
llm_verifier, report_enricher, model_tiers); a test enforces that.
"""
