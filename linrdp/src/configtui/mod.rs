//! `linrdp config` — the configuration, browsable.
//!
//! The left pane is the whole schema as a tree; the right pane is the help for
//! whatever is selected, which is the same text the file's comments are
//! rendered from. One source, two places to read it.
//!
//! Saving re-renders the file from scratch, because serde cannot round-trip
//! YAML comments — so an operator's own comments do not survive, and
//! `config.yaml.bak` is written first for exactly that reason.

mod model;

use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{Frame, Terminal};

use crate::config::Config;
use crate::config::meta::{self, Kind};
use model::{Model, Slot, Source};

/// Restore the terminal, whatever happens to the process.
///
/// A panic inside a raw-mode alternate screen leaves the operator with a shell
/// that does not echo, so the hook and the `Drop` both undo it and nothing
/// else in this crate calls `disable_raw_mode`.
struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> anyhow::Result<Self> {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            Self::restore();
            previous(info);
        }));
        crossterm::terminal::enable_raw_mode().context("enable raw mode")?;
        crossterm::execute!(std::io::stdout(), crossterm::terminal::EnterAlternateScreen)
            .context("enter the alternate screen")?;
        Ok(Self)
    }

    fn restore() {
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = crossterm::execute!(std::io::stdout(), crossterm::terminal::LeaveAlternateScreen);
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        Self::restore();
    }
}

/// What the editor is waiting for.
enum Mode {
    Browse,
    /// Picking one of a key's documented values.
    Choose {
        slot: Slot,
        values: Vec<&'static str>,
        index: usize,
    },
    /// Typing a value.
    Type {
        slot: Slot,
        buffer: String,
    },
    /// Answering "leave without saving?".
    ConfirmQuit,
}

/// `linrdp config [--print]`.
pub(crate) fn run(print_only: bool) -> anyhow::Result<()> {
    let path = crate::config::path().to_path_buf();
    let config = read(&path)?;

    // Without a terminal there is nothing to browse, so show the file — which
    // is the same content, comments and all. This is also the shape that works
    // over ssh in a pipe and in a bug report.
    if print_only || !std::io::stdout().is_terminal() || !std::io::stdin().is_terminal() {
        print!("{}", crate::config::render(&config));
        return Ok(());
    }

    // SAFETY: geteuid takes no arguments, touches no memory and cannot fail.
    let writable = unsafe { libc::geteuid() } == 0;
    let mut model = Model::new(config);

    let _guard = TerminalGuard::enter()?;
    let mut terminal =
        Terminal::new(ratatui::backend::CrosstermBackend::new(std::io::stdout())).context("take over the terminal")?;
    let outcome = event_loop(&mut terminal, &mut model, &path, writable);
    drop(_guard);
    outcome
}

/// Read the file, or start from the defaults when there is none.
///
/// This is the one caller of the defaults that is not a server: editing the
/// configuration of a machine that has none is how you write the first one.
fn read(path: &Path) -> anyhow::Result<Config> {
    let loaded = crate::config::load_or_default(path)?;
    Ok(loaded.config)
}

type Backend = ratatui::backend::CrosstermBackend<std::io::Stdout>;

fn event_loop(terminal: &mut Terminal<Backend>, model: &mut Model, path: &Path, writable: bool) -> anyhow::Result<()> {
    let mut mode = Mode::Browse;
    let mut message = if writable {
        String::new()
    } else {
        format!(
            "read-only: {} belongs to root — run with sudo to change it",
            path.display()
        )
    };

    loop {
        model.clamp();
        terminal
            .draw(|frame| draw(frame, model, &mode, &message, writable))
            .map_err(|error| anyhow::anyhow!("draw the screen: {error}"))?;

        let Event::Key(key) = event::read().context("read a key")? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }

        match &mut mode {
            Mode::ConfirmQuit => match key.code {
                KeyCode::Char('y' | 'Y') => return Ok(()),
                _ => mode = Mode::Browse,
            },

            Mode::Choose { slot, values, index } => match key.code {
                KeyCode::Up => *index = index.saturating_sub(1),
                KeyCode::Down => *index = (*index + 1).min(values.len().saturating_sub(1)),
                KeyCode::Enter => {
                    let chosen = values.get(*index).copied().unwrap_or_default();
                    message = apply(model, *slot, chosen);
                    mode = Mode::Browse;
                }
                KeyCode::Esc => mode = Mode::Browse,
                _ => {}
            },

            Mode::Type { slot, buffer } => match key.code {
                KeyCode::Char(c) => buffer.push(c),
                KeyCode::Backspace => {
                    buffer.pop();
                }
                KeyCode::Enter => {
                    let typed = buffer.clone();
                    message = apply(model, *slot, &typed);
                    mode = Mode::Browse;
                }
                KeyCode::Esc => mode = Mode::Browse,
                _ => {}
            },

            Mode::Browse => match key.code {
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return Ok(()),
                KeyCode::Char('q') | KeyCode::Esc => {
                    if model.dirty {
                        mode = Mode::ConfirmQuit;
                    } else {
                        return Ok(());
                    }
                }
                KeyCode::Up => model.cursor = model.cursor.saturating_sub(1),
                KeyCode::Down => model.cursor = model.cursor.saturating_add(1),
                KeyCode::Home => model.cursor = 0,
                KeyCode::End => model.cursor = usize::MAX,
                KeyCode::Left | KeyCode::Right => {
                    if let Some(row) = model.selected() {
                        if row.expandable {
                            model.toggle(&row.id);
                        }
                    }
                }
                KeyCode::Enter => {
                    let Some(row) = model.selected() else { continue };
                    if row.expandable {
                        model.toggle(&row.id);
                        continue;
                    }
                    let Some(slot) = row.slot else { continue };
                    if !writable {
                        message = "read-only — run `sudo linrdp config` to change anything".to_owned();
                        continue;
                    }
                    mode = editor_for(model, slot);
                }
                KeyCode::Char('x') => {
                    // Clear an override: this listener goes back to inheriting.
                    let Some(row) = model.selected() else { continue };
                    if let (true, Some(slot @ Slot::Override(..))) = (writable, row.slot) {
                        message = match slot.clear(&mut model.config) {
                            Ok(()) => {
                                model.dirty = true;
                                "inherited again".to_owned()
                            }
                            Err(error) => format!("{error:#}"),
                        };
                    }
                }
                KeyCode::Char('a') if writable => {
                    message = match model.add_listener() {
                        Ok(()) => "listener added".to_owned(),
                        Err(error) => format!("{error:#}"),
                    };
                }
                KeyCode::Char('d') if writable => {
                    if let Some(index) = selected_listener(model) {
                        message = match model.remove_listener(index) {
                            Ok(()) => "listener removed".to_owned(),
                            Err(error) => format!("{error:#}"),
                        };
                    }
                }
                KeyCode::Char('s') if writable => {
                    message = match save(&model.config, path) {
                        Ok(backup) => {
                            model.dirty = false;
                            match backup {
                                Some(backup) => format!(
                                    "saved {} (previous version kept as {})",
                                    path.display(),
                                    backup.display()
                                ),
                                None => format!("saved {}", path.display()),
                            }
                        }
                        Err(error) => format!("{error:#}"),
                    };
                }
                _ => {}
            },
        }
    }
}

/// Which listener the cursor is inside, for add/remove.
fn selected_listener(model: &Model) -> Option<usize> {
    let row = model.selected()?;
    match row.slot {
        Some(Slot::Bind(index) | Slot::ListenerAuth(index) | Slot::Override(index, _)) => Some(index),
        _ => row.id.strip_prefix("listeners[")?.split(']').next()?.parse().ok(),
    }
}

/// Pick the editor a key's type calls for.
fn editor_for(model: &Model, slot: Slot) -> Mode {
    match meta::field(slot.schema()).map(|field| &field.kind) {
        Some(Kind::Bool) => {
            let values = vec!["true", "false"];
            let current = slot.get(&model.config);
            let index = usize::from(current != "true");
            Mode::Choose { slot, values, index }
        }
        Some(Kind::Enum(_)) => {
            let values: Vec<&'static str> = meta::values(slot.schema()).iter().map(|v| v.name).collect();
            let current = slot.get(&model.config);
            let index = values.iter().position(|v| *v == current).unwrap_or(0);
            Mode::Choose { slot, values, index }
        }
        _ => Mode::Type {
            slot,
            buffer: slot.get(&model.config),
        },
    }
}

fn apply(model: &mut Model, slot: Slot, raw: &str) -> String {
    match slot.set(&mut model.config, raw) {
        Ok(()) => {
            model.dirty = true;
            String::new()
        }
        Err(error) => format!("{error:#}"),
    }
}

/// Write the file, keeping the previous version.
///
/// The backup is not belt and braces: saving re-renders the file from the
/// metadata table, which is what keeps the comments true to the binary and
/// what makes an operator's own comments disappear. `config.yaml.bak` is where
/// they still are.
fn save(config: &Config, path: &Path) -> anyhow::Result<Option<PathBuf>> {
    crate::config::validate(config)?;
    let backup = if path.exists() {
        let backup = PathBuf::from(format!("{}.bak", path.display()));
        std::fs::copy(path, &backup).with_context(|| format!("keep the previous version as {}", backup.display()))?;
        Some(backup)
    } else {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("mkdir {}", dir.display()))?;
        }
        None
    };
    crate::atomic::write(path, &crate::config::render(config), 0o644)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(backup)
}

// ------------------------------------------------------------------ drawing

fn draw(frame: &mut Frame<'_>, model: &Model, mode: &Mode, message: &str, writable: bool) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(2)])
        .split(frame.area());
    let panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(outer[0]);

    draw_tree(frame, panes[0], model, writable);
    draw_help(frame, panes[1], model);
    draw_footer(frame, outer[1], model, mode, message, writable);

    if let Mode::Choose { values, index, .. } = mode {
        draw_chooser(frame, model, values, *index);
    }
}

fn draw_tree(frame: &mut Frame<'_>, area: Rect, model: &Model, writable: bool) {
    let rows = model.rows();
    let items: Vec<ListItem<'_>> = rows
        .iter()
        .map(|row| {
            let indent = "  ".repeat(row.depth);
            let marker = match row.source {
                Source::Branch => {
                    if row.expanded {
                        "▾ "
                    } else {
                        "▸ "
                    }
                }
                _ => "  ",
            };
            let mut spans = vec![Span::raw(format!("{indent}{marker}{}", row.label))];
            if let Some(value) = &row.value {
                spans.push(Span::raw("  "));
                spans.push(Span::styled(
                    value.clone(),
                    match row.source {
                        Source::Default | Source::Inherited => Style::default().add_modifier(Modifier::DIM),
                        _ => Style::default().add_modifier(Modifier::BOLD),
                    },
                ));
            }
            spans.push(Span::styled(
                match row.source {
                    Source::Default => "  · default",
                    Source::Set => "  ◆ set",
                    Source::Overridden => "  ▲ overridden",
                    Source::Inherited => "  · inherited",
                    Source::Branch => "",
                },
                Style::default().add_modifier(Modifier::DIM),
            ));
            ListItem::new(Line::from(spans))
        })
        .collect();

    let title = if writable {
        " linrdp config "
    } else {
        " linrdp config (read-only) "
    };
    let mut state = ListState::default();
    state.select(Some(model.cursor));
    frame.render_stateful_widget(
        List::new(items)
            .block(Block::default().borders(Borders::ALL).title(title))
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED)),
        area,
        &mut state,
    );
}

/// The help for whatever is selected — branches included, because standing on
/// `features` and learning what the block is for is half of why this exists.
fn draw_help(frame: &mut Frame<'_>, area: Rect, model: &Model) {
    let Some(row) = model.selected() else {
        return;
    };
    let mut lines: Vec<Line<'_>> = Vec::new();

    if let Some(field) = meta::field(row.schema) {
        for line in field.description.split_inclusive(' ').collect::<String>().lines() {
            lines.push(Line::raw(line.to_owned()));
        }
        if let Kind::Enum(values) = &field.kind {
            lines.push(Line::raw(""));
            for value in *values {
                lines.push(Line::from(vec![Span::styled(
                    value.name.to_owned(),
                    Style::default().add_modifier(Modifier::BOLD),
                )]));
                lines.push(Line::raw(format!("  {}", value.gloss)));
            }
        }
        if let Some(default) = field.default {
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                format!("default: {default}"),
                Style::default().add_modifier(Modifier::DIM),
            ));
        }
        // Only for the keys a listener might otherwise expect to override.
        // A listener's own `bind` and `auth` refuse overrides for the trivial
        // reason that they are already per-listener, and saying so under a
        // "service-wide" heading reads as the opposite of what it means.
        if !row.schema.starts_with("listeners") {
            if let Some(reason) = meta::override_refusal(row.schema) {
                lines.push(Line::raw(""));
                lines.push(Line::raw(format!(
                    "service-wide, so no listener may override it: {reason}"
                )));
            }
        }
    }

    if row.source == Source::Inherited {
        lines.push(Line::raw(""));
        lines.push(Line::raw(
            "inherited from the global block; Enter gives this listener its own",
        ));
    }
    if row.source == Source::Overridden {
        lines.push(Line::raw(""));
        lines.push(Line::raw(
            "this listener's own value; x gives it back to the global one",
        ));
    }

    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: true }).block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" {} ", model::leaf_name(row.schema))),
        ),
        area,
    );
}

fn draw_footer(frame: &mut Frame<'_>, area: Rect, model: &Model, mode: &Mode, message: &str, writable: bool) {
    let line = match mode {
        Mode::Type { buffer, slot } => {
            format!(
                "{} = {buffer}_    (Enter to accept, Esc to cancel)",
                model::leaf_name(slot.schema())
            )
        }
        Mode::Choose { .. } => "↑↓ choose   Enter accept   Esc cancel".to_owned(),
        Mode::ConfirmQuit => "unsaved changes — leave anyway? (y/n)".to_owned(),
        Mode::Browse if writable => {
            "↑↓ move   →/Enter open   Enter edit   x inherit   a add listener   d remove   s save   q quit".to_owned()
        }
        Mode::Browse => "↑↓ move   →/Enter open   q quit".to_owned(),
    };

    let status = if message.is_empty() {
        if model.dirty {
            "unsaved changes".to_owned()
        } else {
            String::new()
        }
    } else {
        message.to_owned()
    };

    frame.render_widget(
        Paragraph::new(vec![
            Line::raw(line),
            Line::styled(status, Style::default().add_modifier(Modifier::BOLD)),
        ]),
        area,
    );
}

/// The value picker, over the middle of the screen.
fn draw_chooser(frame: &mut Frame<'_>, model: &Model, values: &[&str], index: usize) {
    let area = frame.area();
    let width = area.width.saturating_sub(10).min(70);
    let height = u16::try_from(values.len().saturating_add(2))
        .unwrap_or(6)
        .min(area.height);
    let popup = Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    };

    let schema = model.selected().map(|row| row.schema).unwrap_or_default();
    let items: Vec<ListItem<'_>> = values
        .iter()
        .map(|value| {
            let gloss = meta::values(schema)
                .iter()
                .find(|v| v.name == *value)
                .map(|v| v.gloss)
                .unwrap_or_default();
            let mut spans = vec![Span::styled(
                (*value).to_owned(),
                Style::default().add_modifier(Modifier::BOLD),
            )];
            if !gloss.is_empty() {
                spans.push(Span::styled(
                    format!("  {}", first_sentence(gloss)),
                    Style::default().add_modifier(Modifier::DIM),
                ));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();

    let mut state = ListState::default();
    state.select(Some(index));
    frame.render_widget(ratatui::widgets::Clear, popup);
    frame.render_stateful_widget(
        List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" {} ", model::leaf_name(schema))),
            )
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED)),
        popup,
        &mut state,
    );
}

/// The picker has one line per value; the pane beside it has the whole gloss.
fn first_sentence(text: &str) -> String {
    text.split_once(". ")
        .map_or_else(|| text.to_owned(), |(first, _)| format!("{first}."))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The screen itself, drawn into a buffer instead of a terminal.
    ///
    /// Cheap insurance for the one thing a reader cannot check by reading:
    /// that a key and its help actually reach the pane they belong in.
    #[test]
    fn the_screen_shows_the_tree_and_the_help_for_what_is_selected() {
        let config = crate::config::load_or_default(Path::new("/nonexistent/linrdp.yaml"))
            .expect("defaults")
            .config;
        let mut model = Model::new(config);
        model.collapsed.clear();
        // Put the cursor on `auth`, whose help lists every value.
        model.cursor = model
            .rows()
            .iter()
            .position(|row| row.slot == Some(Slot::ListenerAuth(0)))
            .expect("the auth row");

        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(140, 40)).expect("terminal");
        terminal
            .draw(|frame| draw(frame, &model, &Mode::Browse, "", true))
            .expect("drawn");

        let screen: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect();

        assert!(screen.contains("listeners"), "the tree is drawn: {screen}");
        assert!(screen.contains("0.0.0.0:3389"), "with the listener in it");
        assert!(screen.contains("greeter"), "the help pane lists every auth value");
        assert!(screen.contains("s save"), "and the footer says how to keep a change");
    }

    /// Saving keeps the previous file, because the save itself is what
    /// discards an operator's hand-written comments: re-rendering from the
    /// metadata table is the only way the comments stay true to the binary.
    #[test]
    fn saving_keeps_the_previous_version() {
        let dir = std::env::temp_dir().join(format!("linrdp-cfgsave-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("config.yaml");

        let original = "listeners:\n  - bind: 0.0.0.0:3389\n    auth: both\n# my own note\n";
        std::fs::write(&path, original).expect("seed");

        let config = crate::config::load_strict(&path).expect("loads");
        let backup = save(&config, &path).expect("saved").expect("a backup");

        assert_eq!(std::fs::read_to_string(&backup).expect("backup"), original);
        assert!(
            !std::fs::read_to_string(&path).expect("saved").contains("my own note"),
            "the note is gone from the file — which is why the backup exists"
        );
        crate::config::load_strict(&path).expect("the service starts on what was saved");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A machine with no configuration is exactly where writing the first one
    /// starts, so the editor opens on the defaults rather than refusing.
    #[test]
    fn the_editor_opens_on_the_defaults_when_there_is_no_file() {
        let missing = std::env::temp_dir().join(format!("linrdp-nocfg-{}.yaml", std::process::id()));
        let _ = std::fs::remove_file(&missing);
        let config = read(&missing).expect("defaults");
        assert_eq!(config.listeners.len(), 1);
    }
}
