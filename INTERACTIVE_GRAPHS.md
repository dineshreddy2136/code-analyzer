# Interactive Dependency Graphs

The dependency analyzer now generates interactive SVG graphs with hover tooltips and optional clickable links for enhanced code exploration.

## Features

### 🔍 **Rich Hover Tooltips**
Every internal function node displays detailed information on hover:
- Function signature with parameters
- File path and line number  
- Source code preview (first 12 lines)
- HTML-escaped for safe rendering

### 🔗 **Clickable Links** (Optional)
Nodes can be configured with clickable links to:
- Open files directly in VS Code (`vscode://file/...`)
- Jump to GitHub/GitLab source lines (`repo_url/file#L123`)
- Custom URL schemes for other editors/tools

### 🎨 **Enhanced Visual Styling**
- **Start node**: Light blue highlight
- **Cycle nodes**: Red double circles with thick borders
- **External nodes**: Dashed ellipses with tooltips
- **Edges**: Color-coded (red for cycle-related dependencies)

## Usage

### 1. Generate Interactive DOT
```bash
python main.py codebase.zip function.txt --emit dot > deps.dot
```

### 2. Render as SVG (Required for Interactivity)
```bash
# High-quality interactive SVG
dot -Tsvg deps.dot -o deps.svg

# Alternative: use neato for different layout
neato -Tsvg deps.dot -o deps.svg
```

### 3. View Interactive Graph
Open the SVG file in:
- **Web browser**: Full interactivity with hover tooltips
- **VS Code**: Built-in SVG preview with hover support
- **Any SVG viewer**: Tooltips work in most modern viewers

### 4. Enable Clickable Links (Future Enhancement)
```python
# In your custom script using the analyzer:
link_mode = ("vscode", "/absolute/path/to/project/root")
# OR
link_mode = ("github", "https://github.com/user/repo/blob/main")

output = emit_dot(edges, start_node, external_edges, cycle_nodes, func_map, link_mode)
```

## Example Tooltip Content

When you hover over a function node, you'll see:
```
cleanup_stale_connections(self, timeout_minutes: int = 30)
test/database.py:54

    def cleanup_stale_connections(self, timeout_minutes: int = 30):
        """Clean up connections that haven't been used recently"""
        cutoff_time = datetime.now() - timedelta(minutes=timeout_minutes)
        
        stale_connections = []
        for conn in self.active_connections:
            if conn['last_used'] and conn['last_used'] < cutoff_time:
                stale_connections.append(conn)
        
        for conn in stale_connections:
            self.return_connection(conn)
```

## Benefits

- **Instant Code Context**: No need to open files to understand function purpose
- **Visual Debugging**: Immediately spot problematic dependency patterns
- **Efficient Navigation**: Click to jump directly to source code
- **Documentation**: Generate professional diagrams for code reviews
- **Accessibility**: Works with standard web technologies

## Technical Notes

- **File Size**: SVG files are larger than PNG but remain manageable for most dependency graphs
- **Performance**: Tooltips are rendered client-side, no server required
- **Compatibility**: Works with any modern web browser or SVG viewer
- **Scalability**: Graphs remain interactive even with 50+ nodes

The interactive graphs transform dependency analysis from static text into dynamic, explorable visualizations that make code understanding intuitive and efficient.
