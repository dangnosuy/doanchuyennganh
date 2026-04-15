"""
ManageAgent — Task manager and orchestrator for MARL pipeline.

Tập trung quản lý toàn bộ workflow pentest từ recon → debate → execute → evaluate → report.
Xử lý task tracking, retry logic, và state management giữa các phases.
"""

import re
import sys
from pathlib import Path
from typing import Optional, List, Dict
from datetime import datetime

_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from shared.utils import parse_prompt, extract_next_tag, extract_send_block, strip_tag
from agents.crawl_agent import CrawlAgent
from agents.red_team import RedTeamAgent
from agents.blue_team import BlueTeamAgent
from agents.exec_agent import ExecAgent


# ═════════════════════════════════════════════════════════════
# CONSTANTS & COLORS
# ═════════════════════════════════════════════════════════════

R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
C = "\033[96m"
B = "\033[1m"
RST = "\033[0m"
DIM = "\033[2m"

MAX_DEBATE_STEPS = 30
MAX_ROUNDS = 5
MIN_DEBATE_ROUNDS = 2
MAX_EXEC_RETRIES = 2


# ═════════════════════════════════════════════════════════════
# TASK TRACKING
# ═════════════════════════════════════════════════════════════

class TaskStatus:
    """Track task status during pipeline execution."""
    NOT_STARTED = "not-started"
    IN_PROGRESS = "in-progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class Task:
    """Represent a trackable task in the pipeline."""
    def __init__(self, name: str, phase: str, description: str = ""):
        self.name = name
        self.phase = phase
        self.description = description
        self.status = TaskStatus.NOT_STARTED
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        self.error: Optional[str] = None

    def start(self):
        self.status = TaskStatus.IN_PROGRESS
        self.start_time = datetime.now()

    def complete(self):
        self.status = TaskStatus.COMPLETED
        self.end_time = datetime.now()

    def fail(self, error: str):
        self.status = TaskStatus.FAILED
        self.error = error
        self.end_time = datetime.now()

    def skip(self):
        self.status = TaskStatus.SKIPPED
        self.end_time = datetime.now()

    def duration(self) -> Optional[float]:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None

    def __str__(self) -> str:
        duration = f" ({self.duration():.1f}s)" if self.duration() else ""
        status_icon = {
            TaskStatus.COMPLETED: "✓",
            TaskStatus.FAILED: "✗",
            TaskStatus.IN_PROGRESS: "▶",
            TaskStatus.SKIPPED: "⊘",
            TaskStatus.NOT_STARTED: "○",
        }.get(self.status, "?")
        return f"{status_icon} {self.name} [{self.status}]{duration}"


# ═════════════════════════════════════════════════════════════
# ORCHESTRATOR
# ═════════════════════════════════════════════════════════════

class ManageAgent:
    """Central orchestrator for MARL pentest pipeline.

    5 Phases:
    1. RECON — CrawlAgent gathers data
    2. DEBATE — Red vs Blue discuss strategy
    3. EXECUTION — ExecAgent runs approved workflow
    4. EVALUATION — Red evaluates results
    5. REPORT — Generate final report
    """

    def __init__(self, run_dir: str):
        self.run_dir = run_dir
        self.start_time = datetime.now()

        # Pipeline state
        self.target_url: Optional[str] = None
        self.recon_path: Optional[str] = None
        self.recon_content: Optional[str] = None
        self.workflow: Optional[str] = None
        self.exec_report: Optional[str] = None
        self.red_evaluation: Optional[str] = None
        self.verdict: str = "REJECTED"
        self.conversation: List[Dict] = []
        self.total_debate_rounds: int = 0
        self.total_exec_attempts: int = 0

        # Agent instances
        self.crawl_agent: Optional[CrawlAgent] = None
        self.exec_agent: Optional[ExecAgent] = None
        self.red_team: Optional[RedTeamAgent] = None
        self.blue_team: Optional[BlueTeamAgent] = None

        # Task tracking
        self.tasks: List[Task] = []
        self._init_tasks()

    def _init_tasks(self):
        """Initialize task list for 5 phases."""
        self.tasks = [
            Task("Phase 1: Recon", "RECON", "Crawl target and gather HTTP traffic"),
            Task("Phase 2: Debate", "DEBATE", "Red/Blue debate attack strategy"),
            Task("Phase 3: Execution", "EXECUTION", "Execute approved workflow"),
            Task("Phase 4: Evaluation", "EVALUATION", "Red evaluates results"),
            Task("Phase 5: Report", "REPORT", "Generate final report"),
        ]

    def _get_task(self, name: str) -> Optional[Task]:
        """Get task by name."""
        return next((t for t in self.tasks if t.name == name), None)

    def _print_task_status(self):
        """Print current task status."""
        print(f"\n{C}{'─' * 60}")
        print(f"  {B}Task Status{RST}")
        print(f"{C}{'─' * 60}{RST}")
        for task in self.tasks:
            icon_color = {
                TaskStatus.COMPLETED: G,
                TaskStatus.FAILED: R,
                TaskStatus.IN_PROGRESS: Y,
                TaskStatus.SKIPPED: DIM,
                TaskStatus.NOT_STARTED: C,
            }.get(task.status, C)
            print(f"{icon_color}{task}{RST}")

    def run_pipeline(self, user_prompt: str) -> Dict:
        """Execute complete MARL pipeline.

        Args:
            user_prompt: URL + credentials

        Returns:
            Result dictionary with verdict, workflow, reports
        """
        try:
            print(f"\n{C}{B}{'='*60}")
            print(f"  ManageAgent — Pipeline Orchestrator")
            print(f"{'='*60}{RST}\n")

            # Parse input
            self.target_url, _ = parse_prompt(user_prompt)
            if not self.target_url:
                raise ValueError("No URL found in prompt")

            self.conversation = [{"speaker": "USER", "content": f"[USER]: {user_prompt}"}]

            # Phase 1: Recon
            self._execute_phase_recon(user_prompt)
            self._print_task_status()

            # Initialize agents after recon
            self._init_agents()

            # Phases 2-4: Debate-Execute-Evaluate loop with retries
            self._execute_debate_execute_loop()
            self._print_task_status()

            # Phase 5: Report
            self._execute_phase_report()
            self._print_task_status()

            return self._make_result_dict()

        except RuntimeError as e:
            print(f"\n{R}[!] Pipeline error: {e}{RST}")
            self._mark_failed(str(e))
            return self._make_result_dict()
        except Exception as e:
            print(f"\n{R}[!] Unexpected error: {e}{RST}")
            import traceback
            traceback.print_exc()
            self._mark_failed(str(e))
            return self._make_result_dict()
        finally:
            self._cleanup()
            self._print_final_summary()

    # ─── Phase 1: RECON ──────────────────────────────────────────

    def _execute_phase_recon(self, user_prompt: str):
        """Phase 1: CrawlAgent collects target data."""
        task = self._get_task("Phase 1: Recon")
        task.start()

        try:
            print(f"\n{C}{B}{'='*60}")
            print(f"  PHASE 1: RECONNAISSANCE")
            print(f"{'='*60}{RST}\n")

            self.crawl_agent = CrawlAgent(working_dir=self.run_dir)
            self.recon_path = self.crawl_agent.run(user_prompt)

            if not self.recon_path or not Path(self.recon_path).exists():
                raise RuntimeError("CrawlAgent failed to create recon.md")

            self.recon_content = Path(self.recon_path).read_text(encoding="utf-8")
            print(f"\n{G}[+] Recon completed: {self.recon_path}{RST}\n")
            task.complete()

        except Exception as e:
            task.fail(str(e))
            raise

    # ─── Phases 2-4: DEBATE → EXECUTE → EVALUATE ──────────────────

    def _execute_debate_execute_loop(self):
        """Phases 2-4: Full debate-execute-evaluate cycle with retries."""
        for attempt in range(1, MAX_EXEC_RETRIES + 2):
            self.total_exec_attempts = attempt

            if attempt > 1:
                print(f"\n{Y}{B}══════════════════════════════════════════")
                print(f"  RETRY #{attempt - 1}/{MAX_EXEC_RETRIES}")
                print(f"══════════════════════════════════════════{RST}\n")

            # Phase 2: Debate
            try:
                self._execute_phase_debate()
            except RuntimeError as e:
                task = self._get_task("Phase 2: Debate")
                task.fail(str(e))
                raise

            # Phase 3: Execution
            try:
                self._execute_phase_execute()
            except Exception as e:
                print(f"{Y}[!] Execution failed: {e}{RST}")
                task = self._get_task("Phase 3: Execution")
                task.fail(str(e))

            # Phase 4: Evaluation
            try:
                self._execute_phase_evaluate()
            except Exception as e:
                task = self._get_task("Phase 4: Evaluation")
                task.fail(str(e))
                raise

            # Check verdict
            if self.verdict in ["SUCCESS", "FAIL"]:
                print(f"\n{G}[+] Pipeline complete with verdict: {self.verdict}{RST}")
                break
            elif self.verdict == "RETRY" and attempt <= MAX_EXEC_RETRIES:
                print(f"\n{Y}[!] Red Team requesting new strategy (retry {attempt}/{MAX_EXEC_RETRIES}){RST}")
                continue
            else:
                break

    def _execute_phase_debate(self):
        """Phase 2: Red vs Blue debate attack strategy."""
        task = self._get_task("Phase 2: Debate")
        task.start()

        print(f"\n{C}{B}{'='*60}")
        print(f"  PHASE 2: RED vs BLUE DEBATE")
        print(f"{'='*60}{RST}\n")

        self.blue_team = BlueTeamAgent(
            target_url=self.target_url,
            recon_context=self.recon_content
        )

        round_num = 0
        red_spoke = False
        blue_spoke = False
        next_turn = "REDTEAM"
        last_caller = "REDTEAM"

        for step in range(MAX_DEBATE_STEPS):
            # RED TEAM
            if next_turn == "REDTEAM":
                if red_spoke and blue_spoke:
                    round_num += 1
                    red_spoke = False
                    blue_spoke = False

                if round_num >= MAX_ROUNDS:
                    print(f"{R}[!] Reached {MAX_ROUNDS} rounds — REJECTED{RST}")
                    raise RuntimeError(f"Debate exhausted {MAX_ROUNDS} rounds without approval")

                print(f"\n{R}{B}══ RED TEAM — Round {round_num + 1}/{MAX_ROUNDS} ══{RST}")
                response = self.red_team.respond(self.conversation)
                tag = extract_next_tag(response)

                self.conversation.append({
                    "speaker": "REDTEAM",
                    "content": f"[REDTEAM]: {response}",
                })
                print(f"{R}{strip_tag(response)}{RST}")
                red_spoke = True

                if tag == "AGENT":
                    last_caller = "REDTEAM"
                    next_turn = "AGENT"
                else:
                    next_turn = "BLUETEAM"

            # BLUE TEAM
            elif next_turn == "BLUETEAM":
                print(f"\n{C}{B}══ BLUE TEAM — Review ══{RST}")
                response = self.blue_team.respond(self.conversation)
                tag = extract_next_tag(response)

                self.conversation.append({
                    "speaker": "BLUETEAM",
                    "content": f"[BLUETEAM]: {response}",
                })
                print(f"{C}{strip_tag(response)}{RST}")
                blue_spoke = True

                if tag == "APPROVED":
                    if round_num + 1 < MIN_DEBATE_ROUNDS:
                        print(f"\n{Y}{B}[GUARDRAIL] Round {round_num + 1}/{MIN_DEBATE_ROUNDS} "
                              f"— insufficient rounds, forcing more review{RST}")
                        self.conversation.append({
                            "speaker": "SYSTEM",
                            "content": (
                                f"[SYSTEM]: Must have at least {MIN_DEBATE_ROUNDS} rounds. "
                                "Ask more verification questions or request changes from Red Team."
                            ),
                        })
                        next_turn = "BLUETEAM"
                    else:
                        print(f"\n{G}{B}══ APPROVED ══{RST}")
                        self.workflow = self._extract_workflow(self.conversation)
                        self.total_debate_rounds += round_num + 1
                        task.complete()
                        return
                elif tag == "AGENT":
                    last_caller = "BLUETEAM"
                    next_turn = "AGENT"
                else:
                    next_turn = "REDTEAM"

            # AGENT
            elif next_turn == "AGENT":
                caller_name = "Red Team" if last_caller == "REDTEAM" else "Blue Team"
                print(f"\n{G}{B}[AGENT] Processing request from {caller_name}...{RST}")

                raw = self.exec_agent.answer(self.conversation, caller=last_caller)
                data = extract_send_block(raw) or raw

                self.conversation.append({
                    "speaker": "AGENT",
                    "content": f"[AGENT]: {data}",
                })
                print(f"{G}{strip_tag(raw)}{RST}")
                next_turn = last_caller

        # Exhausted steps
        raise RuntimeError(f"Debate exhausted {MAX_DEBATE_STEPS} steps without approval")

    def _execute_phase_execute(self):
        """Phase 3: Execute approved workflow."""
        task = self._get_task("Phase 3: Execution")
        task.start()

        print(f"\n{C}{B}{'='*60}")
        print(f"  PHASE 3: EXECUTION")
        print(f"{'='*60}{RST}\n")

        try:
            self.exec_report = self.exec_agent.run_workflow(self.workflow, self.conversation)
            print(f"\n{G}[+] Execution complete{RST}")
            task.complete()
        except Exception as e:
            task.fail(str(e))
            raise

    def _execute_phase_evaluate(self):
        """Phase 4: Red evaluates execution results."""
        task = self._get_task("Phase 4: Evaluation")
        task.start()

        print(f"\n{C}{B}{'='*60}")
        print(f"  PHASE 4: EVALUATION")
        print(f"{'='*60}{RST}\n")

        # Inject execution report into conversation
        self.conversation.append({
            "speaker": "SYSTEM",
            "content": f"[SYSTEM]: Execution report:\n{self.exec_report}",
        })

        try:
            # Red Team evaluates in eval mode
            response = self.red_team.respond(self.conversation)
            self.red_evaluation = response

            self.conversation.append({
                "speaker": "REDTEAM",
                "content": f"[REDTEAM]: {response}",
            })

            # Extract verdict from response
            if "[DONE]" in response and "SUCCESS" in response.upper():
                self.verdict = "SUCCESS"
                print(f"\n{G}[+] Verdict: SUCCESS{RST}")
            elif "[DONE]" in response:
                self.verdict = "FAIL"
                print(f"\n{R}[!] Verdict: FAIL{RST}")
            elif "[BLUETEAM]" in response or "RETRY" in response.upper():
                self.verdict = "RETRY"
                print(f"\n{Y}[!] Verdict: RETRY{RST}")
            else:
                self.verdict = "FAIL"
                print(f"\n{Y}[!] Verdict: FAIL (indeterminate){RST}")

            task.complete()

        except Exception as e:
            task.fail(str(e))
            raise

    # ─── Phase 5: REPORT ──────────────────────────────────────────

    def _execute_phase_report(self):
        """Phase 5: Generate final report."""
        task = self._get_task("Phase 5: Report")
        task.start()

        print(f"\n{C}{B}{'='*60}")
        print(f"  PHASE 5: FINAL REPORT")
        print(f"{'='*60}{RST}\n")

        try:
            report_path = Path(self.run_dir) / "report.md"

            with open(report_path, "w", encoding="utf-8") as f:
                f.write("# MARL Penetration Test Report\n\n")
                f.write(f"**Target:** {self.target_url}\n")
                f.write(f"**Verdict:** {self._verdict_symbol()} {self.verdict}\n")
                f.write(f"**Date:** {datetime.now().isoformat()}\n\n")

                f.write("## Summary\n")
                f.write(f"- Debate Rounds: {self.total_debate_rounds}\n")
                f.write(f"- Execution Attempts: {self.total_exec_attempts}\n")
                f.write(f"- Status: {'✓ Completed' if self.verdict in ['SUCCESS', 'FAIL'] else '✗ Failed'}\n\n")

                if self.workflow:
                    f.write("## Approved Attack Workflow\n")
                    f.write(self.workflow + "\n\n")

                if self.exec_report:
                    f.write("## Execution Report\n")
                    f.write(self.exec_report + "\n\n")

                if self.red_evaluation:
                    f.write("## Red Team Evaluation\n")
                    f.write(self.red_evaluation + "\n\n")

                f.write("## Conversation History\n")
                f.write(f"Total messages: {len(self.conversation)}\n\n")

            print(f"{G}[+] Report written: {report_path}{RST}")
            task.complete()

        except Exception as e:
            task.fail(str(e))
            raise

    # ─── Helpers ──────────────────────────────────────────────────

    def _init_agents(self):
        """Initialize Red/Blue team agents after recon."""
        self.exec_agent = ExecAgent(
            working_dir=self.run_dir,
            target_url=self.target_url,
            recon_md=self.recon_path,
        )
        self.red_team = RedTeamAgent(
            target_url=self.target_url,
            recon_context=self.recon_content
        )

    def _extract_workflow(self, conversation: List[Dict]) -> str:
        """Extract workflow from last Red Team message."""
        for msg in reversed(conversation):
            if msg["speaker"] != "REDTEAM":
                continue
            content = msg["content"]
            lower = content.lower()
            if any(kw in lower for kw in ["chiến lược", "chien luoc", "workflow", "bước 1", "buoc 1"]):
                clean = content
                if clean.startswith("[REDTEAM]:"):
                    clean = clean[len("[REDTEAM]:"):].strip()
                return strip_tag(clean)

        # Fallback
        for msg in reversed(conversation):
            if msg["speaker"] == "REDTEAM":
                clean = msg["content"]
                if clean.startswith("[REDTEAM]:"):
                    clean = clean[len("[REDTEAM]:"):].strip()
                return strip_tag(clean)

        return ""

    def _verdict_symbol(self) -> str:
        """Return emoji for verdict."""
        return {
            "SUCCESS": "✅",
            "FAIL": "❌",
            "RETRY": "⚠️",
            "REJECTED": "❌",
        }.get(self.verdict, "❓")

    def _mark_failed(self, error: str):
        """Mark all remaining tasks as failed."""
        for task in self.tasks:
            if task.status == TaskStatus.NOT_STARTED:
                task.skip()
            elif task.status == TaskStatus.IN_PROGRESS:
                task.fail(error)

    def _cleanup(self):
        """Clean up agent resources."""
        try:
            if self.crawl_agent:
                self.crawl_agent.shutdown()
        except Exception:
            pass

        try:
            if self.exec_agent:
                self.exec_agent.shutdown()
        except Exception:
            pass

    def _print_final_summary(self):
        """Print final execution summary."""
        duration = (datetime.now() - self.start_time).total_seconds()
        print(f"\n{C}{B}{'='*60}")
        print(f"  EXECUTION COMPLETE")
        print(f"{'='*60}{RST}")
        print(f"{G}Target: {self.target_url}{RST}")
        print(f"{self._verdict_symbol()} Verdict: {self.verdict}")
        print(f"⏱  Duration: {duration:.1f}s")
        print(f"📊 Debate rounds: {self.total_debate_rounds}, Attempts: {self.total_exec_attempts}")
        if self.recon_path:
            print(f"📄 Recon: {self.recon_path}")
        print(f"{C}{'='*60}{RST}\n")

    def _make_result_dict(self) -> Dict:
        """Construct result dictionary."""
        return {
            "verdict": self.verdict,
            "target_url": self.target_url,
            "workflow": self.workflow,
            "exec_report": self.exec_report,
            "red_evaluation": self.red_evaluation,
            "debate_rounds": self.total_debate_rounds,
            "exec_attempts": self.total_exec_attempts,
            "recon_path": self.recon_path,
            "report_path": str(Path(self.run_dir) / "report.md"),
            "duration": (datetime.now() - self.start_time).total_seconds(),
        }
