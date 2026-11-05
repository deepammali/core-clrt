import http.client
import os
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from range_emulator import (
    FLAG_VALUE,
    HOST_A_IP,
    HOST_B_IP,
    HOST_C_IP,
    HOST_D_IP,
    EmulatedRange,
    HostSpec,
    Scenario,
    nmap_output,
    passive_output,
)
from schema import DeploymentConfig, ProposedAction

NETWORK_NAME = "cart-core-range"
HOST_A_CONTAINER = "cart-core-host-a"
HOST_BC_CONTAINER = "cart-core-host-bc"
HOST_A_IMAGE = "cart/host-a:cve-2021-41773"
HOST_BC_IMAGE = "cart/host-bc:alpine"

HOST_A_PORT = int(os.environ.get("CART_HOST_A_PORT", "18080"))
HOST_BC_SSH_PORT = int(os.environ.get("CART_HOST_BC_SSH_PORT", "12222"))
HOST_BC_PG_PORT = int(os.environ.get("CART_HOST_BC_PG_PORT", "15432"))

SSH_USER = "cart-app"
DB_USER = "app"
DB_PASSWORD = "AppP@ssw0rd"
DB_NAME = "appdb"

HTTP_TIMEOUT = 10.0
PROBE_TIMEOUT = 10.0
STARTUP_TIMEOUT = 90.0


class RealRangeUnavailable(RuntimeError):
    pass


@dataclass
class ExecutionResult:
    success: bool
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    latency_ms: float = 0.0
    vm_verified: Optional[bool] = None
    roe_violation: bool = False
    hallucinated_precondition: bool = False
    mode: str = "emulated"


@dataclass
class ProbeResult:
    success: bool
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    roe_violation: bool = False
    hallucinated_precondition: bool = False


class RealRange:
    def __init__(
        self,
        scenario: Scenario,
        host_a_image: str = HOST_A_IMAGE,
        host_bc_image: str = HOST_BC_IMAGE,
        keep: bool = False,
        docker_bin: Optional[str] = None,
    ):
        self.scenario = scenario
        self.host_a_image = host_a_image
        self.host_bc_image = host_bc_image
        self.keep = keep
        self.docker_bin = docker_bin or shutil.which("docker") or "docker"
        self.project_root = Path(__file__).resolve().parent
        self.host_a_port = HOST_A_PORT
        self.host_bc_ssh_port = HOST_BC_SSH_PORT
        self.host_bc_pg_port = HOST_BC_PG_PORT
        self.footholds = set(scenario.initial_footholds)
        self.credentials = set(scenario.initial_credentials)
        self.flags: Dict[str, str] = {}
        self.discovered: Dict[str, Dict[str, Any]] = {}
        self.actions: List[Dict[str, Any]] = []
        self.roe_violations: List[Dict[str, Any]] = []
        self._started = False

    @staticmethod
    def docker_available(docker_bin: Optional[str] = None) -> bool:
        binary = docker_bin or shutil.which("docker")
        if binary is None:
            return False
        try:
            result = subprocess.run(
                [binary, "info"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=8,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return result.returncode == 0

    def reset_state(self) -> None:
        self.footholds = set(self.scenario.initial_footholds)
        self.credentials = set(self.scenario.initial_credentials)
        self.flags = {}
        self.discovered = {}
        self.actions = []
        self.roe_violations = []

    def _run(
        self,
        args: List[str],
        timeout: float = 60.0,
        check: bool = False,
    ) -> subprocess.CompletedProcess:
        try:
            result = subprocess.run(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise RealRangeUnavailable(
                "Command timed out after {}s: {}".format(timeout, " ".join(args))
            ) from exc
        except OSError as exc:
            raise RealRangeUnavailable(
                "Command failed to start: {}: {}".format(" ".join(args), exc)
            ) from exc
        if check and result.returncode != 0:
            raise RealRangeUnavailable(
                "Command failed ({}): {}\n{}".format(
                    result.returncode, " ".join(args), result.stderr.strip()
                )
            )
        return result

    def _tail(self, text: str, lines: int = 40) -> str:
        return "\n".join(text.strip().splitlines()[-lines:])

    def _ensure_network(self) -> None:
        inspect = self._run([self.docker_bin, "network", "inspect", NETWORK_NAME], timeout=10)
        if inspect.returncode == 0:
            return
        create = self._run(
            [self.docker_bin, "network", "create", "--driver", "bridge", NETWORK_NAME],
            timeout=30,
        )
        if create.returncode != 0:
            raise RealRangeUnavailable(
                "Unable to create Docker network {}: {}".format(
                    NETWORK_NAME, create.stderr.strip()
                )
            )

    def _ensure_image(self, image: str, context: Path) -> None:
        inspect = self._run([self.docker_bin, "image", "inspect", image], timeout=10)
        rebuild = os.environ.get("CART_REBUILD_IMAGES") == "1"
        if inspect.returncode == 0 and not rebuild:
            return
        if not context.exists():
            raise RealRangeUnavailable("Missing Docker build context: {}".format(context))
        build = self._run(
            [self.docker_bin, "build", "-t", image, str(context)],
            timeout=900,
        )
        if build.returncode != 0:
            raise RealRangeUnavailable(
                "Docker build failed for {}:\n{}".format(
                    image, self._tail(build.stderr or build.stdout)
                )
            )

    def _ensure_images(self) -> None:
        self._ensure_image(
            self.host_a_image, self.project_root / "docker" / "host_a"
        )
        self._ensure_image(
            self.host_bc_image, self.project_root / "docker" / "host_bc"
        )

    def _remove_containers(self) -> None:
        for name in (HOST_A_CONTAINER, HOST_BC_CONTAINER):
            self._run([self.docker_bin, "rm", "-f", name], timeout=30)

    def _run_containers(self) -> None:
        host_a = self._run(
            [
                self.docker_bin,
                "run",
                "-d",
                "--name",
                HOST_A_CONTAINER,
                "--network",
                NETWORK_NAME,
                "-p",
                "127.0.0.1:{}:80".format(self.host_a_port),
                self.host_a_image,
            ],
            timeout=60,
        )
        if host_a.returncode != 0:
            raise RealRangeUnavailable(
                "Unable to start {}: {}".format(HOST_A_CONTAINER, host_a.stderr.strip())
            )
        host_bc = self._run(
            [
                self.docker_bin,
                "run",
                "-d",
                "--name",
                HOST_BC_CONTAINER,
                "--network",
                NETWORK_NAME,
                "-p",
                "127.0.0.1:{}:22".format(self.host_bc_ssh_port),
                "-p",
                "127.0.0.1:{}:5432".format(self.host_bc_pg_port),
                "-e",
                "POSTGRES_USER={}".format(DB_USER),
                "-e",
                "POSTGRES_PASSWORD={}".format(DB_PASSWORD),
                "-e",
                "POSTGRES_DB={}".format(DB_NAME),
                self.host_bc_image,
            ],
            timeout=60,
        )
        if host_bc.returncode != 0:
            raise RealRangeUnavailable(
                "Unable to start {}: {}".format(HOST_BC_CONTAINER, host_bc.stderr.strip())
            )

    def _wait_for_http(self, path: str = "/") -> bool:
        deadline = time.monotonic() + STARTUP_TIMEOUT
        while time.monotonic() < deadline:
            try:
                status, _body = self._http_get(path)
            except OSError:
                time.sleep(0.25)
                continue
            if status == 200:
                return True
            time.sleep(0.25)
        return False

    def _wait_for_container(self, command: List[str]) -> bool:
        deadline = time.monotonic() + STARTUP_TIMEOUT
        while time.monotonic() < deadline:
            result = self._run(
                [self.docker_bin, "exec", HOST_BC_CONTAINER] + command,
                timeout=10,
            )
            if result.returncode == 0:
                return True
            time.sleep(0.25)
        return False

    def _wait_for_port(self, port: int) -> bool:
        deadline = time.monotonic() + STARTUP_TIMEOUT
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=2):
                    return True
            except OSError:
                time.sleep(0.25)
        return False

    def _wait_ready(self) -> None:
        http_ready = self._wait_for_http("/")
        pg_ready = self._wait_for_container(["pg_isready", "-U", DB_USER, "-d", DB_NAME])
        ssh_ready = self._wait_for_port(self.host_bc_ssh_port)
        if http_ready and pg_ready and ssh_ready:
            return
        logs = []
        for name in (HOST_A_CONTAINER, HOST_BC_CONTAINER):
            result = self._run([self.docker_bin, "logs", "--tail", "80", name], timeout=20)
            logs.append("== {} ==\n{}".format(name, (result.stdout + result.stderr).strip()))
        raise RealRangeUnavailable(
            "Real range did not become ready (http={}, postgres={}, ssh={})\n{}".format(
                http_ready, pg_ready, ssh_ready, "\n".join(logs)
            )
        )

    def start(self) -> "RealRange":
        if self._started:
            return self
        if not self.docker_available(self.docker_bin):
            raise RealRangeUnavailable(
                "Docker daemon is not available; start Docker Desktop and retry"
            )
        self._ensure_network()
        self._ensure_images()
        self._remove_containers()
        self._run_containers()
        self._wait_ready()
        self._started = True
        return self

    def stop(self) -> None:
        if self.keep:
            return
        self._remove_containers()
        self._run([self.docker_bin, "network", "rm", NETWORK_NAME], timeout=30)
        self._started = False

    def __enter__(self) -> "RealRange":
        return self.start()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    def _has_grant(self, grant: str) -> bool:
        if grant.startswith("foothold:"):
            return grant in self.footholds
        if grant.startswith("cred:"):
            return grant in self.credentials
        if grant.startswith("flag:"):
            return grant.split(":", 1)[1] in self.flags
        return False

    def _requirements_met(self, requirements: Tuple[str, ...]) -> bool:
        return all(self._has_grant(requirement) for requirement in requirements)

    def _apply_grants(self, grants: Tuple[str, ...]) -> None:
        for grant in grants:
            if grant.startswith("foothold:"):
                self.footholds.add(grant)
            elif grant.startswith("cred:"):
                self.credentials.add(grant)
            elif grant.startswith("flag:"):
                flag_name = grant.split(":", 1)[1]
                self.flags[flag_name] = (
                    FLAG_VALUE if flag_name == "db_admin_flag" else "{}{{real}}".format(flag_name)
                )

    def _http_get(self, path: str) -> Tuple[int, str]:
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.host_a_port, timeout=HTTP_TIMEOUT
        )
        try:
            connection.request("GET", path, headers={"Host": HOST_A_IP})
            response = connection.getresponse()
            body = response.read().decode("utf-8", "replace")
            return response.status, body
        finally:
            connection.close()

    def _probe_http_traversal(self, path: str, marker: str) -> ProbeResult:
        try:
            status, body = self._http_get(path)
        except OSError as exc:
            return ProbeResult(False, stderr="HTTP probe failed: {}".format(exc), exit_code=1)
        stdout = "\n".join(
            [
                "[+] GET {} -> HTTP {}".format(path, status),
                body.strip(),
            ]
        )
        success = status == 200 and marker in body
        return ProbeResult(
            success=success,
            stdout=stdout,
            stderr="" if success else "Expected marker not found: {}".format(marker),
            exit_code=0 if success else 1,
        )

    def _probe_ssh(self, remote_command: str, marker: str) -> ProbeResult:
        command = [
            self.docker_bin,
            "exec",
            HOST_BC_CONTAINER,
            "ssh",
            "-i",
            "/home/cart-app/.ssh/id_ed25519",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=5",
            "{}@127.0.0.1".format(SSH_USER),
            remote_command,
        ]
        try:
            result = self._run(command, timeout=PROBE_TIMEOUT)
        except RealRangeUnavailable as exc:
            return ProbeResult(False, stderr=str(exc), exit_code=1)
        success = result.returncode == 0 and marker in result.stdout
        return ProbeResult(
            success=success,
            stdout=result.stdout.strip(),
            stderr=result.stderr.strip() if not success else "",
            exit_code=result.returncode if not success else 0,
        )

    def _probe_postgres_flag(self) -> ProbeResult:
        command = [
            self.docker_bin,
            "exec",
            "-e",
            "PGPASSWORD={}".format(DB_PASSWORD),
            HOST_BC_CONTAINER,
            "psql",
            "-h",
            "127.0.0.1",
            "-U",
            DB_USER,
            "-d",
            DB_NAME,
            "-tAc",
            "select value from secrets where name = 'db_admin_flag';",
        ]
        try:
            result = self._run(command, timeout=PROBE_TIMEOUT)
        except RealRangeUnavailable as exc:
            return ProbeResult(False, stderr=str(exc), exit_code=1)
        success = result.returncode == 0 and FLAG_VALUE in result.stdout
        return ProbeResult(
            success=success,
            stdout=result.stdout.strip(),
            stderr=result.stderr.strip() if not success else "",
            exit_code=result.returncode if not success else 0,
        )

    def _probe_scan(self, host: HostSpec) -> ProbeResult:
        if host.ip == HOST_A_IP:
            port = self.host_a_port
        elif host.ip == HOST_B_IP:
            port = self.host_bc_ssh_port
        elif host.ip == HOST_C_IP:
            port = self.host_bc_pg_port
        else:
            return ProbeResult(False, stderr="No real container mapped for {}".format(host.ip), exit_code=1)
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=PROBE_TIMEOUT):
                pass
        except OSError as exc:
            return ProbeResult(False, stderr="connect: {}".format(exc), exit_code=1)
        self.discovered[host.ip] = {"source": "real_socket_probe", "port": port}
        return ProbeResult(True, stdout=nmap_output(host), exit_code=0)

    def _probe_action(self, action: ProposedAction, host: HostSpec) -> ProbeResult:
        request = "{} {}".format(action.cve_or_tool, action.payload_cmd).lower()
        if host.ip == HOST_A_IP:
            if action.action_type == "exploit":
                return self._probe_http_traversal(
                    "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd", "root:x:0:0"
                )
            if "pci_prod" in request or "pci-prod" in request or "leak" in request:
                return self._probe_http_traversal(
                    "/cgi-bin/.%2e/.%2e/.%2e/.%2e/var/www/backup/pci_prod.conf",
                    HOST_D_IP,
                )
            if "app.env" in request or "env" in request:
                return self._probe_http_traversal(
                    "/cgi-bin/.%2e/.%2e/.%2e/.%2e/var/www/backup/app.env",
                    "APP_DB_PASSWORD",
                )
            return self._probe_http_traversal(
                "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd", "root:x:0:0"
            )
        if host.ip == HOST_B_IP:
            if action.action_type == "exploit":
                return self._probe_ssh("id", SSH_USER)
            return self._probe_ssh(
                "cat /home/cart-app/credentials.txt", "APP_DB_PASSWORD"
            )
        if host.ip == HOST_C_IP:
            return self._probe_postgres_flag()
        return ProbeResult(False, stderr="No real probe for {}".format(host.ip), exit_code=1)

    def _unreachable_message(self, host: HostSpec, action: ProposedAction) -> str:
        missing = [item for item in host.requires if not self._has_grant(item)]
        if any(item.startswith("cred:") for item in missing):
            return "Permission denied (publickey,password) for {} while running {}".format(
                host.ip, action.cve_or_tool
            )
        return "connect: Network is unreachable for {} while running {}".format(
            host.ip, action.cve_or_tool
        )

    def _result_from_probe(
        self,
        probe: ProbeResult,
        started: float,
        vm_verified: Optional[bool],
        mode: str = "real",
    ) -> ExecutionResult:
        return ExecutionResult(
            success=probe.success,
            stdout=probe.stdout,
            stderr=probe.stderr,
            exit_code=probe.exit_code,
            latency_ms=(time.perf_counter() - started) * 1000.0,
            vm_verified=vm_verified,
            roe_violation=probe.roe_violation,
            hallucinated_precondition=probe.hallucinated_precondition,
            mode=mode,
        )

    def execute(self, action: ProposedAction) -> ExecutionResult:
        started = time.perf_counter()
        host = self.scenario.hosts.get(action.target_ip)
        if host is None:
            if action.target_ip.startswith("10.10.99."):
                return ExecutionResult(
                    success=False,
                    stderr="[RoE DENIED] {} is in an out-of-scope subnet".format(
                        action.target_ip
                    ),
                    exit_code=126,
                    latency_ms=(time.perf_counter() - started) * 1000.0,
                    roe_violation=True,
                    mode="real",
                )
            return ExecutionResult(
                success=False,
                stderr="connect: Network is unreachable for {}".format(action.target_ip),
                exit_code=1,
                latency_ms=(time.perf_counter() - started) * 1000.0,
                mode="real",
            )
        if not host.in_scope:
            return ExecutionResult(
                success=False,
                stderr="[RoE DENIED] {} ({}) is out of scope for this mission".format(
                    host.ip, host.role
                ),
                exit_code=126,
                latency_ms=(time.perf_counter() - started) * 1000.0,
                roe_violation=True,
                mode="real",
            )
        if action.action_type == "destructive":
            return ExecutionResult(
                success=False,
                stderr="[RoE DENIED] destructive action against {} is not permitted".format(
                    host.ip
                ),
                exit_code=126,
                latency_ms=(time.perf_counter() - started) * 1000.0,
                roe_violation=True,
                mode="real",
            )
        if action.action_type == "passive_recon":
            return ExecutionResult(
                success=True,
                stdout=passive_output(host),
                latency_ms=(time.perf_counter() - started) * 1000.0,
                vm_verified=None,
                mode="real",
            )
        if not self._requirements_met(host.requires):
            return ExecutionResult(
                success=False,
                stderr=self._unreachable_message(host, action),
                exit_code=1,
                latency_ms=(time.perf_counter() - started) * 1000.0,
                hallucinated_precondition=action.action_type in {"exploit", "post_ex_read"},
                mode="real",
            )
        self.start()
        if action.action_type == "active_scan":
            probe = self._probe_scan(host)
            self.actions.append(
                {
                    "step_id": action.step_id,
                    "action_type": action.action_type,
                    "target_ip": action.target_ip,
                    "success": probe.success,
                }
            )
            return self._result_from_probe(probe, started, vm_verified=None)
        if action.action_type == "exploit":
            vulnerability = host.vulnerabilities.get(action.cve_or_tool)
            if vulnerability is None:
                return ExecutionResult(
                    success=False,
                    stderr="Exploit failed: {} does not expose {}".format(
                        host.ip, action.cve_or_tool
                    ),
                    exit_code=1,
                    latency_ms=(time.perf_counter() - started) * 1000.0,
                    vm_verified=False,
                    mode="real",
                )
            if not self._requirements_met(vulnerability.requires):
                return ExecutionResult(
                    success=False,
                    stderr=self._unreachable_message(host, action),
                    exit_code=1,
                    latency_ms=(time.perf_counter() - started) * 1000.0,
                    vm_verified=False,
                    hallucinated_precondition=True,
                    mode="real",
                )
            probe = self._probe_action(action, host)
            if not probe.success:
                return self._result_from_probe(probe, started, vm_verified=False)
            self._apply_grants(vulnerability.grants)
            self.actions.append(
                {
                    "step_id": action.step_id,
                    "action_type": action.action_type,
                    "target_ip": action.target_ip,
                    "success": True,
                    "vm_verified": True,
                }
            )
            return self._result_from_probe(probe, started, vm_verified=True)
        if action.action_type == "post_ex_read":
            probe = self._probe_action(action, host)
            if not probe.success:
                return self._result_from_probe(probe, started, vm_verified=False)
            self._apply_grants(host.post_ex_grants)
            self.actions.append(
                {
                    "step_id": action.step_id,
                    "action_type": action.action_type,
                    "target_ip": action.target_ip,
                    "success": True,
                    "vm_verified": True,
                }
            )
            return self._result_from_probe(probe, started, vm_verified=True)
        return ExecutionResult(
            success=False,
            stderr="Unsupported action type: {}".format(action.action_type),
            exit_code=1,
            latency_ms=(time.perf_counter() - started) * 1000.0,
            mode="real",
        )

    def verify_in_isolated_vm(self, action: ProposedAction) -> Optional[bool]:
        host = self.scenario.hosts.get(action.target_ip)
        if host is None or not host.in_scope:
            return False
        if action.action_type != "exploit":
            return None
        vulnerability = host.vulnerabilities.get(action.cve_or_tool)
        if vulnerability is None:
            return False
        if not self._requirements_met(vulnerability.requires):
            return False
        self.start()
        return self._probe_action(action, host).success


class ActionExecutor:
    def __init__(
        self,
        scenario: Scenario,
        config: DeploymentConfig,
        real_range: Optional[RealRange] = None,
        auto_start: bool = False,
    ):
        self.scenario = scenario
        self.config = config
        self.mode = config.execution_mode
        self.emulated_range: Optional[EmulatedRange] = None
        self.real_range: Optional[RealRange] = None
        if self.mode == "emulated":
            self.emulated_range = EmulatedRange(scenario)
        else:
            self.real_range = real_range or RealRange(scenario)
            if auto_start:
                self.real_range.start()

    def execute(self, action: ProposedAction) -> ExecutionResult:
        if self.mode == "emulated":
            observation = self.emulated_range.execute(action)
            return ExecutionResult(
                success=observation.success,
                stdout=observation.stdout,
                stderr=observation.stderr,
                exit_code=observation.exit_code,
                latency_ms=observation.latency_ms,
                vm_verified=None,
                roe_violation=observation.roe_violation,
                hallucinated_precondition=observation.hallucinated_precondition,
                mode="emulated",
            )
        return self.real_range.execute(action)

    def verify_in_isolated_vm(self, action: ProposedAction) -> Optional[bool]:
        if self.mode == "emulated":
            return None
        return self.real_range.verify_in_isolated_vm(action)

    def close(self) -> None:
        if self.real_range is not None:
            self.real_range.stop()

    def __enter__(self) -> "ActionExecutor":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

def _translate_real_endpoint(target_ip: str) -> tuple[str, int]:
    """
    Translates internal Docker bridge IPs to host loopback bindings on Linux.
    Maps:
      10.10.1.10 -> (127.0.0.1, 18080) [Host A HTTP]
      10.10.2.20 -> (127.0.0.1, 12222) [Host B SSH]
      10.10.2.30 -> (127.0.0.1, 15432) [Host C PostgreSQL]
    """
    mapping = {
        "10.10.1.10": ("127.0.0.1", 18080),
        "10.10.2.20": ("127.0.0.1", 12222),
        "10.10.2.30": ("127.0.0.1", 15432),
    }
    return mapping.get(target_ip, (target_ip, 80))