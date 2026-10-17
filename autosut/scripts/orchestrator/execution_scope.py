"""Record what a harness-provided Caldera session can establish."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class AgentExecutionScope(BaseModel):
    """Access granted by orchestration is an assumption, not a compromise result."""

    model_config = ConfigDict(extra='forbid', frozen=True)

    schema_version: Literal['1'] = '1'
    execution_host: str = Field(min_length=1)
    technique_id: str = Field(min_length=1)
    executor: Literal['sandcat'] = 'sandcat'
    agent_bootstrap: Literal['orchestrator_installed'] = 'orchestrator_installed'
    access_origin: Literal['harness_provided_session'] = 'harness_provided_session'
    initial_access_demonstrated: Literal[False] = False
    stealth_evaluated: Literal[False] = False
    interpretation: str = (
        'This dispatch starts with a harness-provided execution session. '
        'A Caldera result alone does not demonstrate initial access, lateral movement, '
        'historical fidelity, or stealth. Those require separate causal evidence.'
    )
