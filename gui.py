"""
GUI application for batch email registration.

Provides a tkinter-based interface for configuring and running
batch email registration tasks.
"""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Callable, List, Optional, Set

from api import (
    RegistrationClient,
    build_base_api,
    build_login_url,
    to_ascii_domain,
)
from config import (
    AppConfig,
    get_app_dir,
    find_config_path,
)
from generators import (
    NameLists,
    PasswordGenerator,
    PasswordMode,
    UsernameGenerator,
    UsernameMode,
)
from utils import (
    OutputFiles,
    RegistrationStats,
    open_directory,
    open_file,
    parse_domain_list,
    validate_count,
    validate_domain,
    validate_prefix,
)


class RegistrationWorker:
    """Worker thread for running registration tasks."""

    MAX_CONSECUTIVE_ERRORS = 50

    def __init__(
        self,
        config: AppConfig,
        domains: List[str],
        target_per_domain: int,
        log_callback: Callable[[str], None],
        progress_callback: Callable[[int], None],
        completion_callback: Callable[[], None],
        stop_event: threading.Event,
    ):
        self.config = config
        self.domains = domains
        self.target_per_domain = target_per_domain
        self.log = log_callback
        self.update_progress = progress_callback
        self.on_complete = completion_callback
        self.stop_event = stop_event

        self.used_emails: Set[str] = set()
        self.stats = RegistrationStats(total_target=target_per_domain * len(domains))

        # Initialize generators
        self.name_lists = NameLists.load_from_files(
            config.first_names_file, config.last_names_file
        )
        self.username_gen = UsernameGenerator(self.name_lists)
        self.password_gen = PasswordGenerator(config.fixed_password)

        # Parse modes
        self.username_mode = UsernameMode(config.username_mode)
        self.password_mode = PasswordMode(config.password_mode)

    def run(self) -> None:
        """Execute the registration task."""
        self.log(f"Config file: {self.config._config_path}")
        self.log(f"Shortlink script: {self.config.shortlink_script} (without /api)")
        self.log(
            f"Target: {self.target_per_domain} per domain, {self.stats.total_target} total"
        )
        self.log(f"Domain list: {', '.join(self.domains)}")

        # Create API client
        client = RegistrationClient(
            timeout=self.config.timeout_sec,
            retries=self.config.retries,
            proxies=self.config.get_proxies(),
            api_key=self.config.api_key or None,
        )

        try:
            with OutputFiles() as output:
                for domain in self.domains:
                    if self.stop_event.is_set():
                        self.log("Stop signal received, finishing up...")
                        break

                    self._process_domain(domain, client, output)

                self._finish(output)
        except Exception as e:
            self.log(f"Error: {e}")
        finally:
            self.on_complete()

    def _process_domain(
        self, domain: str, client: RegistrationClient, output: OutputFiles
    ) -> None:
        """Process registration for a single domain."""
        domain = domain.strip().lower()
        if not domain:
            return

        base_api = build_base_api(self.config.ip, domain)

        self.log("--------------------------------------------------")
        self.log(f"Starting domain: {domain}")
        self.log(f"API: {base_api}")
        self.log(f"Domain (ASCII): {to_ascii_domain(domain)}")

        success_count = 0
        error_streak = 0

        while success_count < self.target_per_domain and not self.stop_event.is_set():
            # Generate credentials
            try:
                email = self.username_gen.generate(
                    self.username_mode, domain, self.config.user_prefix
                )
            except ValueError as e:
                output.write_failure("", "", str(e))
                self.stats.record_failure()
                self.log(f"Generation failed: {e}")
                continue

            password = self.password_gen.generate(self.password_mode)

            # Check for duplicate in this session
            if email in self.used_emails:
                output.write_failure(
                    email, password, "Duplicate username in this session, skipped"
                )
                self.stats.record_failure()
                error_streak += 1
                self.log(f"Duplicate username (this session): {email}")

                if error_streak > self.MAX_CONSECUTIVE_ERRORS:
                    self.log(
                        f"Domain {domain} exceeded {self.MAX_CONSECUTIVE_ERRORS} consecutive errors, switching to next domain"
                    )
                    break
                continue

            self.used_emails.add(email)

            # Attempt registration
            result = client.register(base_api, email, password, domain)

            if result.success:
                output.write_success(email, password)
                url = build_login_url(
                    base_api,
                    email,
                    password,
                    script_name=self.config.shortlink_script,
                    keep_at=self.config.keep_at_in_email,
                )
                output.write_url(email, url)

                self.stats.record_success()
                success_count += 1
                error_streak = 0
                self.update_progress(self.stats.successful)
                self.log(
                    f"Registration successful: {email} ({success_count}/{self.target_per_domain}, domain {domain})"
                )
            else:
                output.write_failure(email, password, result.message)
                self.stats.record_failure()
                error_streak += 1

                if result.is_duplicate:
                    self.log(f"Registration failed (already exists): {email}")
                else:
                    self.log(f"Registration failed: {email} -- {result.message}")

                if error_streak > self.MAX_CONSECUTIVE_ERRORS:
                    self.log(
                        f"Domain {domain} exceeded {self.MAX_CONSECUTIVE_ERRORS} consecutive errors, switching to next domain"
                    )
                    break

        self.log(
            f"Domain {domain} complete: {success_count} / {self.target_per_domain} target"
        )

    def _finish(self, output: OutputFiles) -> None:
        """Log completion summary and open output files."""
        self.log("==================================================")
        self.log(self.stats.get_summary())
        self.log(f"Output files:\n - " + "\n - ".join(output.get_file_names()))
        if self.config.open_folder_when_done:
            output.open_url_file()


class App(tk.Tk):
    """Main application window."""

    def __init__(self):
        super().__init__()

        # Load configuration
        self.config = AppConfig.load()

        # Set window properties
        self.title(self.config.get_app_title())
        self.geometry("1140x420")
        self.minsize(1020, 520)

        # Thread synchronization
        self.stop_flag = threading.Event()
        self.log_queue: queue.Queue[str] = queue.Queue()

        # Registration state
        self.domains: List[str] = []
        self.target_per_domain = 0

        # Build UI
        self._build_ui()

        # Start background tasks
        self._poll_log_queue()

    def _build_ui(self) -> None:
        """Build the user interface."""
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)
        self.columnconfigure(2, weight=2)
        self.rowconfigure(0, weight=1)

        self._build_left_panel()
        self._build_middle_panel()
        self._build_right_panel()

    def _build_left_panel(self) -> None:
        """Build the left panel with basic parameters."""
        frame = ttk.LabelFrame(self, text="Basic Parameters")
        frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        for i in range(14):
            frame.rowconfigure(i, weight=0)
        frame.rowconfigure(1, weight=1)
        frame.columnconfigure(1, weight=1)

        # Variables
        self.var_prefix = tk.StringVar(value=self.config.user_prefix)
        self.var_fixed_pwd = tk.StringVar(value=self.config.fixed_password)
        self.var_ip = tk.StringVar(value=self.config.ip)
        self.var_count = tk.StringVar(value=str(self.config.gen_count))

        # Email prefix
        ttk.Label(frame, text="Email Prefix (1 letter):").grid(
            row=0, column=0, sticky="e", padx=8, pady=6
        )
        ttk.Entry(frame, textvariable=self.var_prefix, width=12).grid(
            row=0, column=1, sticky="we", padx=8, pady=6
        )

        # Domain list
        ttk.Label(frame, text="Email Domain List:").grid(
            row=1, column=0, sticky="ne", padx=8, pady=6
        )
        self.txt_domains = tk.Text(frame, height=4, width=50)
        self.txt_domains.grid(row=1, column=1, sticky="nsew", padx=8, pady=6)
        self.txt_domains.insert("1.0", self.config.domain_list)

        # Fixed password
        ttk.Label(frame, text="Custom Password:").grid(
            row=2, column=0, sticky="e", padx=8, pady=6
        )
        ttk.Entry(frame, textvariable=self.var_fixed_pwd).grid(
            row=2, column=1, sticky="we", padx=8, pady=6
        )

        # Server IP/domain
        ttk.Label(frame, text="Server IP/Domain:").grid(
            row=3, column=0, sticky="e", padx=8, pady=6
        )
        ttk.Entry(frame, textvariable=self.var_ip).grid(
            row=3, column=1, sticky="we", padx=8, pady=6
        )

        # Generation count
        ttk.Label(frame, text="Generation Count:").grid(
            row=4, column=0, sticky="e", padx=8, pady=6
        )
        ttk.Entry(frame, textvariable=self.var_count, width=10).grid(
            row=4, column=1, sticky="w", padx=8, pady=6
        )

        # Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=5, column=0, columnspan=2, sticky="we", padx=8, pady=12)
        btn_frame.columnconfigure(0, weight=1)
        btn_frame.columnconfigure(1, weight=1)
        btn_frame.columnconfigure(2, weight=1)

        self.btn_start = tk.Button(
            btn_frame,
            text="Start",
            command=self._on_start,
            bg="#dc2626",
            fg="white",
            activebackground="#b91c1c",
            activeforeground="white",
            relief="raised",
        )
        self.btn_start.grid(row=0, column=0, sticky="we", padx=6)

        self.btn_stop = ttk.Button(
            btn_frame,
            text="Stop",
            command=self._on_stop,
            state="disabled",
        )
        self.btn_stop.grid(row=0, column=1, sticky="we", padx=6)

        ttk.Button(
            btn_frame,
            text="Open Output Dir",
            command=self._open_output_dir,
        ).grid(row=0, column=2, sticky="we", padx=6)

    def _build_middle_panel(self) -> None:
        """Build the middle panel with mode selections."""
        frame = ttk.Frame(self)
        frame.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(3, weight=1)

        # Username mode
        un_frame = ttk.LabelFrame(frame, text="Username Mode")
        un_frame.grid(row=0, column=0, sticky="we")

        self.var_un_mode = tk.StringVar(value=self.config.username_mode)
        ttk.Radiobutton(
            un_frame, text="Fixed Format", value="fixed", variable=self.var_un_mode
        ).pack(anchor="w", padx=10, pady=4)
        ttk.Radiobutton(
            un_frame,
            text="8-char Random (lowercase/digits, no l/1/o/0)",
            value="rand8",
            variable=self.var_un_mode,
        ).pack(anchor="w", padx=10, pady=4)
        ttk.Radiobutton(
            un_frame,
            text="English Name (first+last, no dot)",
            value="ename",
            variable=self.var_un_mode,
        ).pack(anchor="w", padx=10, pady=4)

        # Password mode
        pw_frame = ttk.LabelFrame(frame, text="Password Mode")
        pw_frame.grid(row=1, column=0, sticky="we", pady=(10, 0))

        self.var_pw_mode = tk.StringVar(value=self.config.password_mode)
        ttk.Radiobutton(
            pw_frame,
            text="Fixed Password (use custom password)",
            value="fixed",
            variable=self.var_pw_mode,
        ).pack(anchor="w", padx=10, pady=4)
        ttk.Radiobutton(
            pw_frame, text="Random 6-digit", value="num6", variable=self.var_pw_mode
        ).pack(anchor="w", padx=10, pady=4)
        ttk.Radiobutton(
            pw_frame,
            text="Strong 9-char (upper/lower/digit)",
            value="strong9",
            variable=self.var_pw_mode,
        ).pack(anchor="w", padx=10, pady=4)

        # Notice label
        self.var_notice = tk.StringVar(value="Notice: Loading...")
        ttk.Label(
            frame,
            textvariable=self.var_notice,
            wraplength=260,
            foreground="#666666",
        ).grid(row=2, column=0, sticky="we", padx=4, pady=(8, 0))

    def _build_right_panel(self) -> None:
        """Build the right panel with results display."""
        frame = ttk.LabelFrame(self, text="Results")
        frame.grid(row=0, column=2, sticky="nsew", padx=10, pady=10)
        frame.rowconfigure(1, weight=1)
        frame.columnconfigure(0, weight=1)

        # Progress bar
        self.progress = ttk.Progressbar(frame, mode="determinate")
        self.progress.grid(row=0, column=0, sticky="we", padx=8, pady=6)

        # Log text area
        self.txt_log = tk.Text(frame, height=20, wrap="word")
        self.txt_log.grid(row=1, column=0, sticky="nsew", padx=8, pady=6)

        # Clear button
        ttk.Button(
            frame,
            text="Clear",
            command=lambda: self.txt_log.delete("1.0", "end"),
        ).grid(row=2, column=0, sticky="e", padx=8, pady=6)

    def _poll_log_queue(self) -> None:
        """Poll the log queue and update the log display."""
        try:
            while True:
                msg = self.log_queue.get_nowait()
                self.txt_log.insert("end", f"{msg}\n")
                self.txt_log.see("end")
        except queue.Empty:
            pass

        self.after(80, self._poll_log_queue)

    def _run_on_ui_thread(self, func: Callable[..., None], *args) -> None:
        """
        Schedule a callable to run on the Tk main thread.

        Tkinter widgets must only be mutated from the main thread.
        """
        try:
            self.after(0, func, *args)
        except tk.TclError:
            # App is likely closing; ignore late background callbacks.
            pass

    def _log(self, message: str) -> None:
        """Add a message to the log queue."""
        self.log_queue.put(message)

    def _update_progress(self, value: int) -> None:
        """Update the progress bar value."""
        self.progress["value"] = value

    def _open_output_dir(self) -> None:
        """Open the output directory in file browser."""
        open_directory(get_app_dir())

    def _open_config_file(self) -> None:
        """Open the configuration file."""
        open_file(find_config_path())

    def _validate_inputs(self) -> Optional[tuple[List[str], int]]:
        """
        Validate all user inputs.

        Returns:
            Tuple of (valid_domains, count) or None if validation fails.
        """
        # Validate prefix
        prefix = self.var_prefix.get().strip()
        if not validate_prefix(prefix):
            messagebox.showerror("Error", "Email prefix must be exactly 1 letter")
            return None

        # Validate domains
        raw_domains = self.txt_domains.get("1.0", "end").strip()
        domains = parse_domain_list(raw_domains)

        if not domains:
            messagebox.showerror("Error", "Please enter at least one email domain")
            return None

        for domain in domains:
            if not validate_domain(domain):
                messagebox.showerror("Error", f"Invalid email domain format: {domain}")
                return None

        # Validate count
        is_valid, count, error = validate_count(self.var_count.get())
        if not is_valid:
            messagebox.showerror("Error", error)
            return None

        return domains, count

    def _save_current_config(self, domains: List[str], count: int) -> None:
        """Save current UI values to configuration."""
        self.config.user_prefix = self.var_prefix.get().strip()
        self.config.domain = domains[0] if domains else ""
        self.config.domain_list = "\n".join(domains)
        self.config.fixed_password = self.var_fixed_pwd.get()
        self.config.ip = self.var_ip.get().strip()
        self.config.gen_count = count
        self.config.username_mode = self.var_un_mode.get()
        self.config.password_mode = self.var_pw_mode.get()
        self.config.save()

        # Reload to ensure consistency
        self.config = AppConfig.load()

    def _on_start(self) -> None:
        """Handle start button click."""
        # Validate inputs
        result = self._validate_inputs()
        if result is None:
            return

        domains, count = result

        # Save configuration
        self._save_current_config(domains, count)

        # Check ename mode requirements
        if self.var_un_mode.get() == "ename":
            name_lists = NameLists.load_from_files(
                self.config.first_names_file, self.config.last_names_file
            )
            if not name_lists.is_valid():
                messagebox.showerror(
                    "Error",
                    "English name mode requires first_names.txt and last_names.txt "
                    "in the same directory (at least 1 line each, letters only).\n"
                    "Please create/edit these files before starting.",
                )
                return

        # Prepare for registration
        self.stop_flag.clear()
        self.domains = domains
        self.target_per_domain = count
        total = count * len(domains)

        self.progress["value"] = 0
        self.progress["maximum"] = total
        self.txt_log.delete("1.0", "end")

        # Update button states
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")

        # Start worker thread
        worker = RegistrationWorker(
            config=self.config,
            domains=domains,
            target_per_domain=count,
            log_callback=self._log,
            progress_callback=lambda v: self._run_on_ui_thread(
                self._update_progress, v
            ),
            completion_callback=lambda: self._run_on_ui_thread(
                self._on_worker_complete
            ),
            stop_event=self.stop_flag,
        )

        threading.Thread(target=worker.run, daemon=True).start()

    def _on_stop(self) -> None:
        """Handle stop button click."""
        self.stop_flag.set()

    def _on_worker_complete(self) -> None:
        """Handle worker completion."""
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
