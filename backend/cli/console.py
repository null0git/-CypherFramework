"""
Interactive CLI Console
Provides a command-line interface similar to Metasploit's msfconsole.
"""

import asyncio
import cmd2
import logging
from typing import Dict, Any, List
from rich.console import Console
from rich.table import Table
from rich.syntax import Syntax
from rich.panel import Panel

logger = logging.getLogger(__name__)

class CypherConsole(cmd2.Cmd):
    """Interactive console for CypherFramework."""
    
    def __init__(self, framework):
        super().__init__()
        self.framework = framework
        self.console = Console()
        self.current_module = None
        self.current_session = None
        
        # Set prompt
        self.prompt = "cypher > "
        
        # Disable built-in commands we don't need
        self.hidden_commands.extend(['alias', 'edit', 'macro', 'run_pyscript', 'run_script'])
        
    async def start(self):
        """Start the interactive console."""
        self.console.print(Panel.fit(
            "[bold green]CypherFramework Console[/bold green]\n"
            "Professional Penetration Testing Framework\n"
            "[dim]Type 'help' for available commands[/dim]",
            border_style="green"
        ))
        
        # Start command loop
        self.cmdloop()
        
    def do_show(self, args):
        """Show various information."""
        parts = args.split()
        if not parts:
            self.console.print("[red]Usage: show <options|modules|sessions|targets|vulns>[/red]")
            return
            
        what = parts[0].lower()
        
        if what == "modules":
            asyncio.run(self._show_modules())
        elif what == "sessions":
            asyncio.run(self._show_sessions())
        elif what == "targets":
            asyncio.run(self._show_targets())
        elif what == "vulns":
            asyncio.run(self._show_vulnerabilities())
        elif what == "options" and self.current_module:
            self._show_module_options()
        else:
            self.console.print(f"[red]Unknown show option: {what}[/red]")
            
    async def _show_modules(self):
        """Show loaded modules."""
        modules = self.framework.modules
        
        table = Table(title="Loaded Modules")
        table.add_column("Name", style="cyan")
        table.add_column("Type", style="magenta")
        table.add_column("Description", style="white")
        table.add_column("Author", style="green")
        
        for name, module in modules.items():
            table.add_row(
                name,
                module.get('type', 'unknown'),
                module.get('description', '')[:50] + '...' if len(module.get('description', '')) > 50 else module.get('description', ''),
                module.get('author', 'Unknown')
            )
            
        self.console.print(table)
        
    async def _show_sessions(self):
        """Show active sessions."""
        sessions = await self.framework.list_sessions()
        
        table = Table(title="Active Sessions")
        table.add_column("ID", style="cyan")
        table.add_column("Type", style="magenta")
        table.add_column("Target", style="yellow")
        table.add_column("Created", style="green")
        table.add_column("Status", style="white")
        
        for session in sessions:
            table.add_row(
                session['id'][:8],
                session['type'],
                session['target'],
                session['created_at'][:19],
                "Active" if session['active'] else "Inactive"
            )
            
        self.console.print(table)
        
    async def _show_targets(self):
        """Show discovered targets."""
        targets = await self.framework.get_targets()
        
        table = Table(title="Discovered Targets")
        table.add_column("IP Address", style="cyan")
        table.add_column("Hostname", style="magenta")
        table.add_column("OS", style="yellow")
        table.add_column("Services", style="green")
        table.add_column("Status", style="white")
        
        for target in targets:
            services = ", ".join([f"{s['port']}/{s['service']}" for s in target.get('services', [])])
            table.add_row(
                target['ip_address'],
                target.get('hostname', 'Unknown'),
                f"{target.get('os_type', 'Unknown')} {target.get('os_version', '')}".strip(),
                services[:30] + '...' if len(services) > 30 else services,
                target.get('status', 'Unknown')
            )
            
        self.console.print(table)
        
    async def _show_vulnerabilities(self):
        """Show discovered vulnerabilities."""
        vulns = await self.framework.get_vulnerabilities()
        
        table = Table(title="Discovered Vulnerabilities")
        table.add_column("CVE", style="red")
        table.add_column("Target", style="cyan")
        table.add_column("Service", style="magenta")
        table.add_column("Severity", style="yellow")
        table.add_column("Status", style="green")
        
        for vuln in vulns:
            severity_color = {
                'Critical': 'red',
                'High': 'yellow',
                'Medium': 'blue',
                'Low': 'green'
            }.get(vuln.get('severity', 'Unknown'), 'white')
            
            table.add_row(
                vuln['cve_id'],
                vuln['ip_address'],
                f"{vuln.get('service', 'unknown')}:{vuln.get('port', '?')}",
                f"[{severity_color}]{vuln.get('severity', 'Unknown')}[/{severity_color}]",
                vuln.get('status', 'Unknown')
            )
            
        self.console.print(table)
        
    def _show_module_options(self):
        """Show current module options."""
        if not self.current_module:
            self.console.print("[red]No module selected[/red]")
            return
            
        module = self.framework.modules[self.current_module]
        options = module['instance'].options
        
        table = Table(title=f"Options for {self.current_module}")
        table.add_column("Name", style="cyan")
        table.add_column("Current Value", style="yellow")
        table.add_column("Required", style="red")
        table.add_column("Description", style="white")
        
        for name, option in options.items():
            table.add_row(
                name,
                str(option.get('value', '')),
                "Yes" if option.get('required', False) else "No",
                option.get('description', '')
            )
            
        self.console.print(table)
        
    def do_use(self, args):
        """Select a module to use."""
        if not args:
            self.console.print("[red]Usage: use <module_name>[/red]")
            return
            
        module_name = args.strip()
        
        if module_name in self.framework.modules:
            self.current_module = module_name
            self.prompt = f"cypher ({module_name}) > "
            self.console.print(f"[green]Using module: {module_name}[/green]")
            self._show_module_options()
        else:
            self.console.print(f"[red]Module not found: {module_name}[/red]")
            
    def do_set(self, args):
        """Set module option."""
        if not self.current_module:
            self.console.print("[red]No module selected. Use 'use <module>' first.[/red]")
            return
            
        parts = args.split(maxsplit=1)
        if len(parts) != 2:
            self.console.print("[red]Usage: set <option> <value>[/red]")
            return
            
        option_name, value = parts
        module = self.framework.modules[self.current_module]
        
        try:
            module['instance'].set_option(option_name, value)
            self.console.print(f"[green]{option_name} => {value}[/green]")
        except ValueError as e:
            self.console.print(f"[red]Error: {e}[/red]")
            
    def do_run(self, args):
        """Run the current module."""
        if not self.current_module:
            self.console.print("[red]No module selected. Use 'use <module>' first.[/red]")
            return
            
        # Run module asynchronously
        asyncio.run(self._run_module())
        
    async def _run_module(self):
        """Execute the current module."""
        module = self.framework.modules[self.current_module]
        
        # Validate options
        validation = module['instance'].validate_options()
        if not validation['valid']:
            self.console.print(f"[red]Missing required options: {validation['missing']}[/red]")
            return
            
        self.console.print("[yellow]Running module...[/yellow]")
        
        # Get options
        options = {name: opt['value'] for name, opt in module['instance'].options.items()}
        
        # Execute module
        result = await self.framework.run_module(self.current_module, options)
        
        if result['success']:
            self.console.print("[green]Module executed successfully[/green]")
            if 'result' in result:
                self.console.print(Panel(str(result['result']), title="Output"))
        else:
            self.console.print(f"[red]Module failed: {result.get('error', 'Unknown error')}[/red]")
            
    def do_sessions(self, args):
        """Interact with sessions."""
        parts = args.split()
        
        if not parts:
            asyncio.run(self._show_sessions())
            return
            
        if parts[0] == "-i" and len(parts) > 1:
            # Interact with session
            session_id = parts[1]
            asyncio.run(self._interact_session(session_id))
        else:
            self.console.print("[red]Usage: sessions [-i session_id][/red]")
            
    async def _interact_session(self, session_id):
        """Interact with a specific session."""
        # Find full session ID
        sessions = await self.framework.list_sessions()
        full_session_id = None
        
        for session in sessions:
            if session['id'].startswith(session_id):
                full_session_id = session['id']
                break
                
        if not full_session_id:
            self.console.print(f"[red]Session not found: {session_id}[/red]")
            return
            
        self.current_session = full_session_id
        self.console.print(f"[green]Interacting with session {session_id}[/green]")
        self.console.print("[dim]Type 'exit' to return to main console[/dim]")
        
        # Session interaction loop
        while True:
            try:
                command = input(f"session ({session_id}) > ")
                
                if command.strip().lower() == 'exit':
                    break
                    
                if command.strip():
                    result = await self.framework.execute_on_session(full_session_id, command)
                    
                    if result.get('success'):
                        output = result.get('output', '')
                        if output:
                            self.console.print(output)
                    else:
                        self.console.print(f"[red]Error: {result.get('error', 'Unknown error')}[/red]")
                        
            except KeyboardInterrupt:
                break
            except EOFError:
                break
                
        self.current_session = None
        self.console.print("[green]Returned to main console[/green]")
        
    def do_search(self, args):
        """Search modules."""
        if not args:
            self.console.print("[red]Usage: search <term>[/red]")
            return
            
        search_term = args.lower()
        matches = []
        
        for name, module in self.framework.modules.items():
            if (search_term in name.lower() or 
                search_term in module.get('description', '').lower() or
                search_term in module.get('cve', '').lower()):
                matches.append((name, module))
                
        if matches:
            table = Table(title=f"Search Results for '{args}'")
            table.add_column("Name", style="cyan")
            table.add_column("Type", style="magenta")
            table.add_column("Description", style="white")
            
            for name, module in matches:
                table.add_row(
                    name,
                    module.get('type', 'unknown'),
                    module.get('description', '')[:60] + '...' if len(module.get('description', '')) > 60 else module.get('description', '')
                )
                
            self.console.print(table)
        else:
            self.console.print(f"[yellow]No modules found matching '{args}'[/yellow]")
            
    def do_info(self, args):
        """Show detailed module information."""
        module_name = args.strip() if args else self.current_module
        
        if not module_name:
            self.console.print("[red]Usage: info <module_name> or select a module first[/red]")
            return
            
        if module_name not in self.framework.modules:
            self.console.print(f"[red]Module not found: {module_name}[/red]")
            return
            
        module = self.framework.modules[module_name]
        info = module['instance'].get_info()
        
        # Create info panel
        info_text = f"""[bold]Name:[/bold] {info.get('name', 'Unknown')}
[bold]Description:[/bold] {info.get('description', 'No description')}
[bold]Author:[/bold] {info.get('author', 'Unknown')}
[bold]Version:[/bold] {info.get('version', 'Unknown')}
[bold]Type:[/bold] {info.get('type', 'unknown')}"""

        if 'cve' in info and info['cve']:
            info_text += f"\n[bold]CVE:[/bold] {info['cve']}"
            
        if 'references' in info and info['references']:
            info_text += f"\n[bold]References:[/bold] {', '.join(info['references'])}"
            
        self.console.print(Panel(info_text, title=f"Module Info: {module_name}"))
        
    def do_back(self, args):
        """Return to main context."""
        self.current_module = None
        self.current_session = None
        self.prompt = "cypher > "
        self.console.print("[green]Returned to main context[/green]")
        
    def do_exit(self, args):
        """Exit the console."""
        self.console.print("[yellow]Shutting down CypherFramework...[/yellow]")
        return True
        
    def do_quit(self, args):
        """Quit the console."""
        return self.do_exit(args)