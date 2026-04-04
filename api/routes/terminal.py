"""
api/routes/terminal.py — Secure terminal execution bridge.
Provides a restricted way for users to execute CLI commands from the web UI.
"""

import asyncio
import logging
import subprocess
import shlex
import os
import sys
from pathlib import Path
from typing import AsyncGenerator

ROOT = Path(__file__).resolve().parent.parent.parent
from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter()

class CommandRequest(BaseModel):
    command: str

def safe_command(cmd: str) -> bool:
    """
    Verifies if the command is allowed and safe from shell injection.
    Allows dynamic arguments but blocks shell metacharacters.
    """
    # 1. Block known shell metacharacters to prevent command injection
    forbidden_chars = [";", "&", "|", "`", "$", "(", ")", "[", "]", "{", "}", "*", "?", "!", "\n"]
    if any(char in cmd for char in forbidden_chars):
        return False

    # 2. Verify command starts with approved prefixes
    allowed_prefixes = [
        "python run.py cli scan run",
        "python run.py cli scan wizard",
        "python run.py cli report list",
        "python run.py cli report show",
        "python run.py cli auth status"
    ]
    
    # Check if the base command (ignoring arguments) starts with an allowed prefix
    # We split both and check if the prefix parts match the start of the command parts
    cmd_parts = shlex.split(cmd)
    for prefix in allowed_prefixes:
        prefix_parts = shlex.split(prefix)
        if cmd_parts[:len(prefix_parts)] == prefix_parts:
            return True
            
    return False

async def stream_command_output(cmd_args: list[str]) -> AsyncGenerator[str, None]:
    """Runs a command and streams its output via SSE."""
    try:
        # Use sys.executable to ensure we use the same Python environment
        if cmd_args[0] == "python":
            cmd_args[0] = sys.executable

        process = await asyncio.create_subprocess_exec(
            *cmd_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=str(ROOT), # Ensure relative paths to run.py work
            env={**os.environ, "PYTHONUNBUFFERED": "1", "TERM": "xterm-256color"}
        )

        while True:
            line = await process.stdout.readline()
            if not line:
                break
            
            yield f"data: {line.decode().rstrip()}\n\n"
        
        await process.wait()
        yield f"data: [TERMINAL] Execution complete with exit code {process.returncode}\n\n"
        yield "event: complete\ndata: {}\n\n"

    except Exception as e:
        import traceback
        logger.error(f"Execution error: {traceback.format_exc()}")
        yield f"data: [ERROR] Execution failed: {str(e)} — check system environment.\n\n"

@router.post("/run")
async def run_command(req: CommandRequest):
    """Bridge endpoint to execute restricted CLI commands."""
    # 1. Block known shell metacharacters
    forbidden_chars = [";", "&", "|", "`", "$", "(", ")", "[", "]", "{", "}", "*", "?", "!", "\n"]
    found_bad = [c for c in forbidden_chars if c in req.command]
    if found_bad:
        chars_str = " ".join(found_bad)
        raise HTTPException(
            status_code=400, 
            detail=f"Security Violation: Restricted characters detected ({chars_str}). Connection refused."
        )

    if not safe_command(req.command):
        raise HTTPException(
            status_code=400, 
            detail="Command extraction signature mismatch. Restricted environment."
        )

    cmd_args = shlex.split(req.command)
    
    return StreamingResponse(
        stream_command_output(cmd_args),
        media_type="text/event-stream"
    )
