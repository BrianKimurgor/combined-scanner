import signal
import threading
from typing import Annotated, NoReturn

import typer

from scanner.logging_setup import configure_logging
from scanner.settings import Settings

app = typer.Typer()
admin = typer.Typer(help="Administer the scan server.")

SERVER_ERROR = 2


def _fail(message: str) -> NoReturn:
    typer.echo(message, err=True)
    raise typer.Exit(SERVER_ERROR)


def _settings() -> Settings:
    try:
        return Settings.from_env()
    except ValueError as exc:
        _fail(f"Configuration error: {exc}")


def _database(settings: Settings):  # type: ignore[no-untyped-def]
    try:
        from scanner.db.session import init_db, make_engine, make_session_factory
    except ImportError as exc:
        _fail(f"The server needs extra packages: pip install 'code-scanner[server]' ({exc})")
    engine = make_engine(settings)
    init_db(engine)
    return make_session_factory(engine)


@app.command()
def serve(
    host: Annotated[
        str, typer.Option(help="Bind address; keep loopback behind a TLS proxy.")
    ] = "127.0.0.1",
    port: int = 8000,
) -> None:
    """Run the scan API."""
    settings = _settings()
    try:
        import uvicorn

        from scanner.api.app import create_app
    except ImportError as exc:
        _fail(f"The server needs extra packages: pip install 'code-scanner[server]' ({exc})")
    configure_logging(settings)
    if settings.sandbox_mode == "local":
        typer.echo("WARNING: SCANNER_SANDBOX=local runs scans without a sandbox.", err=True)
    uvicorn.run(create_app(settings), host=host, port=port)


@app.command()
def worker(
    once: Annotated[bool, typer.Option(help="Exit when the queue is empty.")] = False,
) -> None:
    """Process queued scans, one sandbox container each."""
    from scanner.worker.runner import run_worker

    settings = _settings()
    configure_logging(settings)
    factory = _database(settings)
    if settings.sandbox_mode == "local":
        typer.echo("WARNING: SCANNER_SANDBOX=local runs scans without a sandbox.", err=True)
    stop = threading.Event()
    signals = (signal.SIGINT, signal.SIGTERM)
    previous = {
        sig: signal.signal(sig, lambda *_: stop.set()) for sig in signals
    }  # finish, then exit
    try:
        processed = run_worker(settings, factory, once=once, should_stop=stop.is_set)
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    typer.echo(f"processed {processed} scan(s)")


@admin.command("create-key")
def create_key(name: Annotated[str, typer.Argument(help="A label for the key owner.")]) -> None:
    """Create an API key. It is shown once and only its hash is stored."""
    from scanner.db import repo
    from scanner.db.session import session_scope

    factory = _database(_settings())
    try:
        with session_scope(factory) as session:
            key = repo.create_api_key(session, name)
    except ValueError as exc:
        _fail(str(exc))
    typer.echo(key)
    typer.echo("Store this key now; it cannot be shown again.", err=True)


@admin.command("list-keys")
def list_keys() -> None:
    """Show every API key by name with its scan count; secrets are never stored."""
    from scanner.db import repo
    from scanner.db.session import session_scope

    factory = _database(_settings())
    with session_scope(factory) as session:
        rows = repo.list_api_keys(session)
    for key, scans, last in rows:
        state = "revoked" if key.revoked else "active"
        seen = last.date().isoformat() if last else "never"
        typer.echo(f"{key.name}\t{state}\t{scans} scan(s)\tlast scan {seen}")


@admin.command("revoke-key")
def revoke_key(name: Annotated[str, typer.Argument(help="The key's name.")]) -> None:
    """Disable a key and end its browser sessions."""
    from scanner.db import repo
    from scanner.db.session import session_scope

    factory = _database(_settings())
    try:
        with session_scope(factory) as session:
            repo.revoke_api_key(session, name)
    except ValueError as exc:
        _fail(str(exc))
    typer.echo(f"revoked {name}")


@admin.command("rotate-key")
def rotate_key(name: Annotated[str, typer.Argument(help="The key's name.")]) -> None:
    """Issue a new secret for a key; the old one stops working at once."""
    from scanner.db import repo
    from scanner.db.session import session_scope

    factory = _database(_settings())
    try:
        with session_scope(factory) as session:
            key = repo.rotate_api_key(session, name)
    except ValueError as exc:
        _fail(str(exc))
    typer.echo(key)
    typer.echo("Store this key now; it cannot be shown again.", err=True)


@admin.command("prune")
def prune_command(
    days: Annotated[
        int | None, typer.Option(min=1, help="Keep this many days; default SCANNER_RETENTION_DAYS.")
    ] = None,
    dry_run: Annotated[bool, typer.Option(help="Only report what would be deleted.")] = False,
) -> None:
    """Delete finished scans past the retention period, with their reports and leftovers."""
    from scanner.retention import prune

    settings = _settings()
    result = prune(settings, _database(settings), days=days, dry_run=dry_run)
    verb = "would remove" if dry_run else "removed"
    typer.echo(
        f"{verb} {result.scans} scan(s), {result.sessions} expired session(s), "
        f"{result.leftovers} leftover file(s)"
    )


@admin.command("mirror-update")
def mirror_update(
    ecosystems: Annotated[
        str | None, typer.Option(help="Comma-separated OSV ecosystems; default is a common set.")
    ] = None,
    skip_osv: Annotated[bool, typer.Option(help="Do not fetch the OSV archives.")] = False,
    skip_trivy: Annotated[bool, typer.Option(help="Do not fetch the Trivy databases.")] = False,
) -> None:
    """Download vulnerability databases for offline scans (needs internet, run on a schedule)."""
    from scanner import mirror

    settings = _settings()
    names = [e.strip() for e in ecosystems.split(",") if e.strip()] if ecosystems else None
    try:
        if not skip_osv:
            done = mirror.update_osv(settings.mirror_dir, names or list(mirror.DEFAULT_ECOSYSTEMS))
            typer.echo(f"osv: {len(done)} ecosystem(s) updated")
        if not skip_trivy:
            mirror.update_trivy(settings.mirror_dir)
            typer.echo("trivy: databases updated")
    except (mirror.MirrorError, OSError) as exc:
        _fail(f"Mirror update failed: {exc}")


@admin.command("mirror-status")
def mirror_status(
    max_age_days: Annotated[int, typer.Option(min=1, help="Mark older data as stale.")] = 7,
) -> None:
    """Show what the offline mirror holds and how old it is."""
    from datetime import UTC, datetime, timedelta

    from scanner import mirror

    settings = _settings()
    now = datetime.now(UTC)
    for entry in mirror.status(settings.mirror_dir):
        if not entry.present or entry.updated is None:
            state = "missing"
        elif now - entry.updated > timedelta(days=max_age_days):
            state = "stale"
        else:
            state = "fresh"
        updated = entry.updated.date().isoformat() if entry.updated else "-"
        typer.echo(f"{entry.name}\t{state}\t{updated}\t{entry.detail}")
