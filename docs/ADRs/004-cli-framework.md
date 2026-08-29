# ARCHITECTURE DECISION RECORD 004
## Industry Standard Format for ADRs (2026)

## Document Identification
- **ADR ID**: 004
- **Title**: CLI Framework with Clap 4.x Derive API
- **Status**: Accepted
- **Date**: 2026-08-28
- **Author**: ForgeCode / RapidWebs
- **Stakeholders**: RapidWebs Engineering, Operations

## Table of Contents
1. [Context](#1-context)
2. [Decision](#2-decision)
3. [Status](#3-status)
4. [Consequences](#4-consequences)
5. [Implications](#5-implications)
6. [Related Documents](#6-related-documents)

---

## 1. Context

### Problem Statement
rw_secstore needs a command-line interface that is:
- Discoverable (help, subcommand help)
- Scriptable (JSON output, exit codes)
- Extensible (new commands without breaking changes)
- User-friendly (completions, colored output, progress)
- Maintainable (type-safe, minimal boilerplate)

### Drivers
- **Developer Experience**: Easy to add new commands
- **User Experience**: Consistent, discoverable, scriptable
- **Maintenance**: Type-safe, compile-time validation
- **Standards**: POSIX/GNU CLI conventions

### Assumptions
- Clap 4.x with derive API is stable and feature-complete
- Shell completions generated at build time
- Color output via `anstyle`/`clap` built-in
- JSON output for all commands via global flag

### Constraints
- Single binary
- No TUI (Text UI) in v1
- No interactive prompts (non-interactive by default)

## 2. Decision

### Decision Statement
**Use Clap 4.x with derive API for CLI framework, with global options for database path, password, output format, and verbosity.**

### Considered Alternatives

#### Alternative 1: `structopt` (deprecated, merged into Clap)
- **Pros**: Was the standard
- **Cons**: Deprecated, use Clap derive directly

#### Alternative 2: `argh` (Google)
- **Pros**: Lightweight, fast
- **Cons**: Less features, no derive API in same way, smaller ecosystem

#### Alternative 3: `clap` Builder API (manual)
- **Pros**: Full control
- **Cons**: Verbose, error-prone, harder to maintain

#### Alternative 4: Custom argument parsing
- **Pros**: Zero dependencies
- **Cons**: Reinventing wheel, poor UX, maintenance burden

### Decision Rationale
Clap 4.x derive API provides:
1. **Type Safety**: Compile-time validation of CLI structure
2. **Discoverability**: Auto-generated help, usage, completions
3. **Extensibility**: New commands = new structs
4. **Scriptability**: Global `--json` flag, consistent exit codes
5. **Ecosystem**: Standard in Rust CLI tools
6. **Features**: Arg groups, conflicts, requirements, env vars, value parsers

### Implementation Approach

```rust
use clap::{Parser, Subcommand, Args, ValueEnum};

#[derive(Parser)]
#[command(name = "rw-secstore", version, about, long_about = None)]
#[command(global_setting = clap::AppSettings::DeriveDisplayOrder)]
struct Cli {
    #[command(flatten)]
    global: GlobalOptions,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Args)]
struct GlobalOptions {
    #[arg(long, global = true, env = "RW_SECSTORE_DB_PATH")]
    db_path: Option<PathBuf>,

    #[arg(long, global = true, env = "RW_SECSTORE_PASSWORD")]
    password: Option<String>,

    #[arg(long, global = true, env = "RW_SECSTORE_PASSWORD_FILE")]
    password_file: Option<PathBuf>,

    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Table)]
    format: OutputFormat,

    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    #[arg(short, long, global = true)]
    quiet: bool,

    #[arg(long, global = true)]
    no_color: bool,

    #[arg(long, global = true, env = "RW_SECSTORE_CONFIG")]
    config: Option<PathBuf>,
}

#[derive(Copy, Clone, ValueEnum)]
enum OutputFormat {
    Table,
    Json,
    Csv,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new keystore
    Init(InitArgs),

    /// Unlock keystore (cache KEK)
    Unlock(UnlockArgs),

    /// Lock keystore (clear KEK)
    Lock,

    /// Show keystore status
    Status,

    /// CA management
    #[command(subcommand)]
    Ca(CaCommands),

    /// Certificate management
    #[command(subcommand)]
    Cert(CertCommands),

    /// Key/secret management
    #[command(subcommand)]
    Key(KeyCommands),

    /// Backup and restore
    #[command(subcommand)]
    Backup(BackupCommands),

    /// Audit log queries
    Audit(AuditArgs),

    /// Configuration management
    #[command(subcommand)]
    Config(ConfigCommands),

    /// Generate shell completions
    Completion(CompletionArgs),
}

// Each subcommand group follows same pattern
#[derive(Subcommand)]
enum CaCommands {
    /// Create a new CA
    Create(CaCreateArgs),
    /// List CAs
    List(CaListArgs),
    /// Show CA details
    Show(CaShowArgs),
    /// Import CA
    Import(CaImportArgs),
    /// Export CA
    Export(CaExportArgs),
    /// Soft delete CA
    Delete(CaDeleteArgs),
    /// Permanently delete CA
    Purge(CaPurgeArgs),
}
```

## 3. Status
**Accepted** - Ready for implementation

## 4. Consequences

### 4.1 Positive Consequences
- Type-safe CLI with compile-time checks
- Auto-generated help and completions
- Consistent UX across all commands
- Easy to add new commands
- Global options work uniformly
- JSON output for automation

### 4.2 Negative Consequences
- Clap adds ~500KB to binary
- Derive macros increase compile time slightly
- Learning curve for advanced features

### 4.3 Neutral Consequences
- Command structure mirrors SPEC command list

## 5. Implications

### 5.1 Architectural Implications
- `cli` module with command handlers
- Each command → handler function returning `Result<Output>`
- `Output` trait with `render(format)` for table/JSON/CSV
- Global options parsed once, passed to handlers

### 5.2 Technical Implications
- Dependencies: `clap` with `derive`, `env`, `str` features
- `clap_complete` for shell completions
- `colored`/`anstyle` for colored output
- `tabled` or `comfy-table` for table rendering

### 5.3 Organizational Implications
- CLI design review before implementation
- Consistent naming conventions across commands

### 5.4 Financial Implications
- No cost

### 5.5 Schedule Implications
- CLI framework: ~1 day
- Each command group: ~1-2 days

## 6. Related Documents
- **SPEC-2026-001**: Core specification (CLI interface section)
- **Reference**: minica CLI structure
- **Reference**: db-keystore CLI structure