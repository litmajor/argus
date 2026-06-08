use std::sync::{Arc, atomic::AtomicBool};
use std::time::{Duration, Instant};

use crossterm::{terminal::{enable_raw_mode, disable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen}, execute, event::{self, Event as CEvent, KeyCode}};
use ratatui::{Terminal, backend::CrosstermBackend, layout::{Constraint, Direction, Layout}, widgets::{Block, Borders, Paragraph, List, ListItem, Row, Table}, style::{Style, Modifier, Color}};
use chrono::{Local, Utc, TimeZone};
use std::collections::{HashSet, VecDeque};
use std::sync::Mutex;
use once_cell::sync::Lazy;

static UI_MSGS: Lazy<Mutex<VecDeque<crate::runtime::events::UiMessage>>> = Lazy::new(|| Mutex::new(VecDeque::new()));

fn centered_rect(width: u16, height: u16, r: ratatui::layout::Rect) -> ratatui::layout::Rect {
    let x = (r.width.saturating_sub(width)) / 2;
    let y = (r.height.saturating_sub(height)) / 2;
    ratatui::layout::Rect { x: r.x + x, y: r.y + y, width, height }
}

fn current_visible_procs() -> Vec<crate::domains::process::state::ProcessInfo> {
    if let Some(s) = crate::runtime::get_latest_state() {
        let mut procs: Vec<_> = s.processes.values().cloned().collect();
        procs.sort_by(|a,b| b.cpu_percent.partial_cmp(&a.cpu_percent).unwrap_or(std::cmp::Ordering::Equal));
        procs.into_iter().take(12).collect()
    } else { Vec::new() }
}

fn get_selected_pid(idx: usize) -> Option<u32> {
    let v = current_visible_procs();
    if v.is_empty() { None } else { v.get(idx).map(|p| p.pid) }
}

fn current_visible_count() -> Option<usize> { Some(current_visible_procs().len()) }

fn get_descendants(pid: u32) -> Vec<u32> {
    let mut out: Vec<u32> = Vec::new();
    if let Some(st) = crate::runtime::get_latest_state() {
        let mut stack: Vec<u32> = vec![pid];
        while let Some(cur) = stack.pop() {
            let children = st.lineage.get_children(cur);
            for c in children.iter() {
                out.push(*c);
                stack.push(*c);
            }
        }
    }
    out
}

fn find_visible_index_by_pid(pid: u32) -> Option<usize> {
    let v = current_visible_procs();
    for (i, p) in v.into_iter().enumerate() {
        if p.pid == pid { return Some(i); }
    }
    None
}

pub fn run(running: Arc<AtomicBool>) {
    // Initialize terminal
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen).ok();
    enable_raw_mode().ok();
    let backend = CrosstermBackend::new(std::io::stdout());
    let mut terminal = Terminal::new(backend).unwrap();

    // Throttle UI/runtime tick to reduce polling frequency (was 1s)
    let tick_rate = Duration::from_millis(4000);
    let mut last_tick = Instant::now();
    // selection index within the Top Processes list
    let mut selected_idx: usize = 0;
    // pending confirmation: (action_char, pid)
    let mut pending_confirm: Option<(char,u32)> = None;
    // expanded pids for tree view
    let mut expanded: HashSet<u32> = HashSet::new();
    // investigation mode pid (show full investigation screen)
    let mut investigation: Option<u32> = None;
    // keep local subscriptions alive for the lifetime of the UI
    let mut _local_subs: Vec<crate::runtime::events::Subscription> = Vec::new();

    // subscribe to UI messages and enqueue them for display
    let sub_ui = crate::runtime::events::subscribe_to_ui_messages(Box::new(|m| {
        let mut q = UI_MSGS.lock().unwrap();
        q.push_back(m.clone());
        while q.len() > 200 { q.pop_front(); }
    }));
    _local_subs.push(sub_ui);

    while running.load(std::sync::atomic::Ordering::SeqCst) {
        // drive runtime to update state (silent)
        crate::runtime::start(true);

        // render UI
            // mark UI active
            crate::runtime::set_ui_active(true);
            terminal.draw(|f| {
            let size = f.area();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([
                    Constraint::Length(3), // header
                    Constraint::Length(3), // stats
                    Constraint::Length(10), // top area (processes + detail)
                    Constraint::Length(7), // findings
                    Constraint::Min(5),    // events
                ].as_ref())
                .split(size);

            // Header
            let header = Paragraph::new("ARGUS SSA").block(Block::default().borders(Borders::ALL));
            f.render_widget(header, chunks[0]);

            // Stats line: CPU sum, MEM total, PROCS count, Security highest status
            let state = crate::runtime::get_latest_state();
            let (cpu_total, mem_total, proc_count, sec_status) = if let Some(s) = state {
                let mut cpu=0.0f32; let mut mem=0.0f32; let mut cnt=0usize;
                for p in s.processes.values() { cpu += p.cpu_percent; mem += p.memory_mb; cnt += 1; }
                let max = crate::domains::security::state::max_score();
                let status = crate::domains::security::state::SecurityScores::map_score_to_status(max);
                (cpu, mem, cnt, format!("{:?}", status))
            } else { (0.0, 0.0, 0usize, "Unknown".to_string()) };
            let stats = format!("CPU {:.1}%   MEM {:.1}MB   PROCS {}   Security: {}", cpu_total, mem_total, proc_count, sec_status);
            let stats_p = Paragraph::new(stats).block(Block::default().borders(Borders::ALL));
            f.render_widget(stats_p, chunks[1]);

            // Top area: split horizontally into processes (left) and detail (right)
            let top_chunks = Layout::default().direction(Direction::Horizontal).constraints([Constraint::Percentage(60), Constraint::Percentage(40)]).split(chunks[2]);
            // Left: Top processes table
            let table_block = Block::default().borders(Borders::ALL).title("Top Processes");
            let inner = top_chunks[0];
            let visible = current_visible_procs();
            // keep selection within bounds
            if !visible.is_empty() {
                if selected_idx >= visible.len() { selected_idx = visible.len() - 1; }
            } else { selected_idx = 0; }
            let rows: Vec<Row> = visible.iter().enumerate().map(|(i,p)| {
                let score = crate::domains::security::state::get_process_score(p.pid);
                let mut r = Row::new(vec![p.pid.to_string(), p.name.clone(), format!("{:.1}%", p.cpu_percent), format!("{}%", score)]);
                if i == selected_idx { r = r.style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)); }
                r
            }).collect();
            let widths = vec![Constraint::Length(7), Constraint::Percentage(50), Constraint::Length(8), Constraint::Length(8)];
            let table = Table::new(rows, widths)
                .header(Row::new(vec!["PID","NAME","CPU","SCORE"]).style(Style::default().add_modifier(Modifier::BOLD)))
                .block(table_block);
            f.render_widget(table, inner);

            // Right: Detail panel for selected process
            let detail_block = Block::default().borders(Borders::ALL).title("Details");
            let detail_area = top_chunks[1];
            let detail_text = if let Some(pid) = get_selected_pid(selected_idx) {
                if let Some(s) = crate::runtime::get_latest_state() {
                    if let Some(p) = s.processes.get(&pid) {
                        let score = crate::domains::security::state::get_process_score(p.pid);
                        let status = format!("{:?}", crate::domains::security::state::status_for_pid(p.pid));
                        let identity = p.identity.as_ref().map(|id| format!("{} {} {}", id.path.clone().unwrap_or_default(), id.signer.clone().unwrap_or_default(), id.company.clone().unwrap_or_default())).unwrap_or_else(|| "<unknown>".to_string());
                        // ancestry as a simple tree (top -> ... -> parent -> selected)
                        let mut tree_lines: Vec<String> = Vec::new();
                        if let Some(st) = crate::runtime::get_latest_state() {
                            let anc = st.lineage.get_ancestors(p.pid);
                            // anc is [parent, grandparent, ...]; reverse to top-first
                            let mut names: Vec<String> = Vec::new();
                            for a in anc.iter().rev() {
                                if let Some(pp) = st.processes.get(a) { names.push(format!("{}({})", pp.name, pp.pid)); }
                            }
                            // append selected
                            names.push(format!("{}({})", p.name, p.pid));
                            // build tree with indentation
                            for (i, n) in names.iter().enumerate() {
                                if i == 0 { tree_lines.push(n.clone()); }
                                else {
                                    let indent = "    ".repeat(i - 1);
                                    tree_lines.push(format!("{}└─ {}", indent, n));
                                }
                            }
                            // immediate children of selected
                            let children = st.lineage.get_children(p.pid);
                            if !children.is_empty() {
                                for c in children.iter() {
                                    if let Some(cp) = st.processes.get(c) {
                                        tree_lines.push(format!("    └─ {}({})", cp.name, cp.pid));
                                    }
                                }
                            }
                        }
                        // contributions
                        let contribs = crate::domains::security::state::get_contributions(p.pid);
                        let mut contrib_text = String::new();
                        if !contribs.is_empty() {
                            for (label, delta) in contribs.iter() {
                                let friendly = match label.as_str() {
                                    "script_engine" => "Script engine",
                                    "powershell" => "PowerShell",
                                    "interactive_console" => "Interactive console",
                                    "spawned_from_devtool" => "Spawned from devtool",
                                    "unsigned" => "Unsigned binary",
                                    "verification_failed" => "Signature verification failed",
                                    "network_activity" => "Network activity",
                                    "behavior_threshold_severe" => "Behavior (severe)",
                                    "behavior_threshold_high" => "Behavior (high)",
                                    "behavior_threshold_medium" => "Behavior (medium)",
                                    "set" => "Explicit set",
                                    other => other,
                                };
                                contrib_text.push_str(&format!("+{} {}\n", delta, friendly));
                            }
                        }

                        let ancestry_text = if tree_lines.is_empty() { "<none>".to_string() } else { tree_lines.join("\n") };

                        format!("PID: {}\nName: {}\nParent: {}\n{}\nCPU: {:.1}%\nMEM: {:.1} MB\nThreads: {}\nScore: {}% ({})\nIdentity: {}\n\nContributions:\n{}",
                            p.pid, p.name, p.parent_pid, ancestry_text, p.cpu_percent, p.memory_mb, p.threads, score, status, identity, contrib_text)
                    } else { "<not found>".to_string() }
                } else { "<no state>".to_string() }
            } else { "<no selection>".to_string() };
            let detail_par = Paragraph::new(detail_text).block(detail_block).style(Style::default());
            f.render_widget(detail_par, detail_area);

            // Findings
            let find_block = Block::default().borders(Borders::ALL).title("Findings");
            let findings_area = chunks[3];
            let items = crate::surfaces::findings::recent_list_items();
            let list = List::new(items).block(find_block);
            f.render_widget(list, findings_area);

            // Events — recent process events
            let ev_block = Block::default().borders(Borders::ALL).title("Events");
            let mut lines: Vec<ListItem> = Vec::new();
            // first include UI messages (if any)
            {
                let q = UI_MSGS.lock().unwrap();
                for m in q.iter().rev().take(10) {
                    let s = format!("[UI:{}] {}", m.topic, m.body.replace('\n', " "));
                    lines.push(ListItem::new(s));
                }
            }
            // then include recent process events
            let evs = crate::domains::process::storage::get_events();
            for (ts, e) in evs.into_iter().rev().take(10) {
                let t = match Utc.timestamp_opt(ts, 0).single() {
                    Some(dt) => dt.with_timezone(&Local).format("%H:%M:%S").to_string(),
                    None => Utc.timestamp_opt(0, 0).single().unwrap().with_timezone(&Local).format("%H:%M:%S").to_string(),
                };
                // human readable mapping
                let s = match e {
                    crate::domains::process::events::ProcessEvent::Started(info) => format!("[{}] {} started (PID {})", t, info.name, info.pid),
                    crate::domains::process::events::ProcessEvent::Terminated(pid) => format!("[{}] PID {} terminated", t, pid),
                    crate::domains::process::events::ProcessEvent::CpuSpike { pid, cpu } => format!("[{}] PID {} CPU spike {:.1}%", t, pid, cpu),
                    crate::domains::process::events::ProcessEvent::FamilyCpuSpike { family, cpu } => format!("[{}] {} family CPU spike {:.1}%", t, family, cpu),
                    crate::domains::process::events::ProcessEvent::FamilyNormalized { family } => format!("[{}] {} family normalized", t, family),
                };
                lines.push(ListItem::new(s));
            }
            let ev_list = List::new(lines).block(ev_block);
            f.render_widget(ev_list, chunks[4]);

            // Confirmation modal overlay (if pending)
            if let Some((act, pid)) = pending_confirm {
                // centered rect
                let w = 50u16;
                let h = 5u16;
                let area = centered_rect(w, h, f.area());
                let msg = match act {
                    'k' => format!("Confirm KILL PID {}? (y/n)", pid),
                    's' => format!("Confirm SUSPEND PID {}? (y/n)", pid),
                    _ => format!("Confirm action on PID {}? (y/n)", pid),
                };
                let block = Block::default().borders(Borders::ALL).title("Confirm");
                let p = Paragraph::new(msg).block(block).style(Style::default().fg(Color::Red));
                f.render_widget(p, area);
            }
            // Investigation modal
            if let Some(ipid) = investigation {
                let w = 70u16;
                let h = 18u16;
                let area = centered_rect(w, h, f.area());
                let block = Block::default().borders(Borders::ALL).title("Process Investigation");

                // build investigation text
                let mut lines: Vec<String> = Vec::new();
                if let Some(st) = crate::runtime::get_latest_state() {
                    if let Some(p) = st.processes.get(&ipid) {
                        lines.push(format!("{} ({})", p.name, p.pid));
                        lines.push(String::new());
                        // Path
                        let path = p.identity.as_ref().and_then(|id| id.path.clone()).unwrap_or_else(|| "<unknown>".to_string());
                        lines.push(format!("Path:\n{}", path));
                        // Parent
                        let parent_str = st.processes.get(&p.parent_pid).map(|pp| format!("{} ({})", pp.name, pp.pid)).unwrap_or_else(|| "<none>".to_string());
                        lines.push(format!("Parent: {}", parent_str));
                        // Children
                        let kids = st.lineage.get_children(p.pid);
                        if kids.is_empty() {
                            lines.push("Children: none".to_string());
                        } else {
                            lines.push("Children:".to_string());
                            for c in kids.iter() {
                                if let Some(cp) = st.processes.get(c) { lines.push(format!(" - {} ({})", cp.name, cp.pid)); }
                            }
                        }
                        // Connections (sockets opened)
                        let behavior = crate::domains::security::state::get_behavior(p.pid);
                        if behavior.sockets_opened > 0 {
                            lines.push(format!("Connections: {} socket(s) opened (addresses not available)", behavior.sockets_opened));
                        } else {
                            lines.push("Connections: none".to_string());
                        }
                        lines.push(String::new());
                        // Risk Factors
                        lines.push("Risk Factors:".to_string());
                        let contribs = crate::domains::security::state::get_contributions(p.pid);
                        if contribs.is_empty() { lines.push(" - none".to_string()); }
                        else {
                            for (label, delta) in contribs.iter() {
                                let friendly = match label.as_str() {
                                    "script_engine" => "Script engine",
                                    "powershell" => "PowerShell",
                                    "interactive_console" => "Interactive console",
                                    "spawned_from_devtool" => "Spawned from devtool",
                                    "unsigned" => "Unsigned binary",
                                    "verification_failed" => "Signature verification failed",
                                    "network_activity" => "Network activity",
                                    "behavior_threshold_severe" => "Behavior (severe)",
                                    "behavior_threshold_high" => "Behavior (high)",
                                    "behavior_threshold_medium" => "Behavior (medium)",
                                    "set" => "Explicit set",
                                    other => other,
                                };
                                lines.push(format!(" +{} {}", delta, friendly));
                            }
                        }
                        lines.push(String::new());
                        // Command line (not available in current collectors)
                        lines.push(format!("Command Line: {}", "<not available>"));
                    } else { lines.push("Process not found in snapshot".to_string()); }
                } else { lines.push("No state available".to_string()); }

                let text = lines.join("\n");
                let p = Paragraph::new(text).block(block).style(Style::default()).wrap(ratatui::widgets::Wrap { trim: true });
                f.render_widget(p, area);
            }
        }).ok();

        // handle input: quit on 'q'
        let timeout = tick_rate.checked_sub(last_tick.elapsed()).unwrap_or_else(|| Duration::from_secs(0));
        if event::poll(timeout).unwrap_or(false) {
            if let CEvent::Key(key) = event::read().unwrap() {
                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Up => { if selected_idx > 0 { selected_idx -= 1; } },
                    KeyCode::Down => { selected_idx = selected_idx.saturating_add(1); },
                    KeyCode::Enter => {
                        // open investigation screen for selected pid
                        if let Some(pid) = get_selected_pid(selected_idx) { investigation = Some(pid); }
                    }
                    KeyCode::Char('t') => { if let Some(pid) = get_selected_pid(selected_idx) { crate::surfaces::process::show_lineage(pid); } }
                    KeyCode::Char('g') => { if let Some(pid) = get_selected_pid(selected_idx) { crate::surfaces::process::show_graph(pid); } }
                    KeyCode::Char('f') => { if let Some(pid) = get_selected_pid(selected_idx) { let body = pid.to_string(); crate::runtime::event_bus::publish(crate::runtime::events::UiMessage { topic: "focus_findings".to_string(), body }); } }
                    KeyCode::Char('k') => {
                        if let Some(pid) = get_selected_pid(selected_idx) { pending_confirm = Some(('k', pid)); }
                    }
                    KeyCode::Char('s') => {
                        if let Some(pid) = get_selected_pid(selected_idx) { pending_confirm = Some(('s', pid)); }
                    }
                    KeyCode::Char('e') => {
                        // toggle expand for selected pid
                        if let Some(pid) = get_selected_pid(selected_idx) {
                            if expanded.contains(&pid) { expanded.remove(&pid); } else { expanded.insert(pid); }
                        }
                    }
                    KeyCode::Char('E') => {
                        // expand full subtree (add all descendants)
                        if let Some(pid) = get_selected_pid(selected_idx) {
                            let desc = get_descendants(pid);
                            for d in desc { expanded.insert(d); }
                            expanded.insert(pid);
                        }
                    }
                    KeyCode::Char('c') => {
                        // collapse selected pid subtree
                        if let Some(pid) = get_selected_pid(selected_idx) {
                            let desc = get_descendants(pid);
                            for d in desc { expanded.remove(&d); }
                            expanded.remove(&pid);
                        }
                    }
                    KeyCode::Char('y') => {
                        if let Some((act, pid)) = pending_confirm.take() {
                            match act {
                                'k' => { let _ = crate::actions::kill(pid); }
                                's' => { let _ = crate::actions::suspend(pid); }
                                _ => {}
                            }
                        }
                    }
                    KeyCode::Char('n') => { pending_confirm = None; }
                    _ => {}
                }
                // keep selected_idx within available range after potential increment
                if let Some(cnt) = current_visible_count() { if cnt == 0 { selected_idx = 0 } else if selected_idx >= cnt { selected_idx = cnt - 1 }; }
            }
        }

        // If investigation screen is open, handle navigation keys (Left=parent, Right=first child) and closing
        if let Some(ipid) = investigation {
            if event::poll(Duration::from_millis(10)).unwrap_or(false) {
                if let CEvent::Key(k) = event::read().unwrap() {
                    match k.code {
                        KeyCode::Esc | KeyCode::Char('q') => { investigation = None; }
                        KeyCode::Left => {
                            // go to parent if available
                            if let Some(st) = crate::runtime::get_latest_state() {
                                if let Some(parent) = st.lineage.get_parent(ipid) {
                                    investigation = Some(parent);
                                    if let Some(idx) = find_visible_index_by_pid(parent) { selected_idx = idx; }
                                }
                            }
                        }
                        KeyCode::Right => {
                            // go to first child if available
                            if let Some(st) = crate::runtime::get_latest_state() {
                                let children = st.lineage.get_children(ipid);
                                if let Some(first) = children.into_iter().next() {
                                    investigation = Some(first);
                                    if let Some(idx) = find_visible_index_by_pid(first) { selected_idx = idx; }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        if last_tick.elapsed() >= tick_rate { last_tick = Instant::now(); }
    }

    // restore terminal
    disable_raw_mode().ok();
    execute!(std::io::stdout(), LeaveAlternateScreen).ok();
    // unset UI active
    crate::runtime::set_ui_active(false);
}
