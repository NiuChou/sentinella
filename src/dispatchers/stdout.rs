use comfy_table::{
    presets::UTF8_FULL_CONDENSED, Attribute, Cell, CellAlignment, Color, ContentArrangement, Table,
};

use crate::reporters::task_decomposer::{Priority, Task};

/// Print tasks to the terminal as a formatted, color-coded table.
///
/// Tasks are grouped by priority (P0 first). When `dry_run` is `true` a
/// `[DRY RUN]` banner is shown above the table.
pub fn dispatch(tasks: &[Task], dry_run: bool) {
    if tasks.is_empty() {
        println!("  No tasks to dispatch.");
        return;
    }

    if dry_run {
        println!();
        println!("  [DRY RUN] The following tasks would be dispatched:");
    }

    // Build a sorted copy so we don't mutate the input.
    let mut sorted: Vec<&Task> = tasks.iter().collect();
    sorted.sort_by_key(|t| t.priority);

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Priority")
                .add_attribute(Attribute::Bold)
                .fg(Color::White)
                .set_alignment(CellAlignment::Center),
            Cell::new("Type")
                .add_attribute(Attribute::Bold)
                .fg(Color::White),
            Cell::new("Title")
                .add_attribute(Attribute::Bold)
                .fg(Color::White),
            Cell::new("Effort")
                .add_attribute(Attribute::Bold)
                .fg(Color::White)
                .set_alignment(CellAlignment::Center),
        ]);

    for task in &sorted {
        let priority_color = priority_color(task.priority);

        table.add_row(vec![
            Cell::new(task.priority_str())
                .fg(priority_color)
                .add_attribute(Attribute::Bold)
                .set_alignment(CellAlignment::Center),
            Cell::new(task.task_type.to_string()),
            Cell::new(&task.title),
            Cell::new(task.effort_str()).set_alignment(CellAlignment::Center),
        ]);
    }

    println!();
    println!("{table}");
    println!("  Total: {} tasks", sorted.len());
    println!();
}

fn priority_color(priority: Priority) -> Color {
    match priority {
        Priority::P0 => Color::Red,
        Priority::P1 => Color::Yellow,
        Priority::P2 => Color::Cyan,
    }
}
