"""Retrieval-Augmented Generation. Retrieval is permission-filtered: OPA decides which documents the caller
may read BEFORE any ranking, so an unauthorised passage can never reach the agent, the reply or the logs."""
