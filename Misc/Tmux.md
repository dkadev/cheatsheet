First, clone the [Tmux Plugin Manager](https://github.com/tmux-plugins/tpm) repo to our home directory.

```shell
git clone https://github.com/tmux-plugins/tpm ~/.tmux/plugins/tpm
```

Next, create a `.tmux.conf` file in the home directory.

```shell
touch ~/.tmux.conf
```

The config file should have the following contents:

```plain
# List of plugins

set -g @plugin 'tmux-plugins/tpm'
set -g @plugin 'tmux-plugins/tmux-sensible'
set -g @plugin 'tmux-plugins/tmux-logging'

# Initialize TMUX plugin manager (keep at bottom)
run '~/.tmux/plugins/tpm/tpm'
```

After creating this config file, we need to execute it in our current session, so the settings in the `.tmux.conf` file take effect. We can do this with the [source](https://www.geeksforgeeks.org/source-command-in-linux-with-examples/) command.

```shell
tmux source ~/.tmux.conf
```

Once in the session, type `[Ctrl] + [B]` and then hit `[Shift] + [I]` (or `prefix` + `[Shift] + [I]` if you are not using the default prefix key), and the plugins will install (this could take around 5 seconds to complete).

## Cheatsheet

### Session Control (from the command line)

| `tmux`                                  | Start a new session                                         |
| --------------------------------------- | ----------------------------------------------------------- |
| `tmux new -s <session-name>`            | Start a new session with the name chosen                    |
| `tmux ls`                               | List all sessions                                           |
| `tmux attach -t <target-session>`       | Re-attach a detached session                                |
| `tmux attach -d -t <target-session>`    | Re-attach a detached session (and detach it from elsewhere) |
| `tmux kill-session -t <target-session>` | Delete session                                              |
### Pane Control

| `Ctrl` `b`, `"`        | Split pane horizontally                  |
| ---------------------- | ---------------------------------------- |
| `Ctrl` `b`, `%`        | Split pane vertically                    |
| `Ctrl` `b`, `o`        | Next pane                                |
| `Ctrl` `b`, `;`        | Previous pane                            |
| `Ctrl` `b`, `q`        | Show pane numbers                        |
| `Ctrl` `b`, `z`        | Toggle pane zoom                         |
| `Ctrl` `b`, `!`        | Convert pane into a window               |
| `Ctrl` `b`, `x`        | Kill current pane                        |
| `Ctrl` `b`, `Ctrl` `O` | Swap panes                               |
| `Ctrl` `b`, `t`        | Display clock                            |
| `Ctrl` `b`, `q`        | Transpose two letters (delete and paste) |
| `Ctrl` `b`, `{`        | Move to the previous pane                |
| `Ctrl` `b`, `}`        | Move to the next pane                    |
| `Ctrl` `b`, `Space`    | Toggle between pane layouts              |
| `Ctrl` `b`, `↑`        | Resize pane (make taller)                |
| `Ctrl` `b`, `↓`        | Resize pane (make smaller)               |
| `Ctrl` `b`, `←`        | Resize pane (make wider)                 |
| `Ctrl` `b`, `→`        | Resize pane (make narrower)              |
### Window Control

| `Ctrl` `b`, `c` | Create new window     |
| --------------- | --------------------- |
| `Ctrl` `b`, `d` | Detach from session   |
| `Ctrl` `b`, `,` | Rename current window |
| `Ctrl` `b`, `&` | Close current window  |
| `Ctrl` `b`, `w` | List windows          |
| `Ctrl` `b`, `p` | Previous window       |
| `Ctrl` `b`, `n` | Next window           |
### Logging
| `Ctrl b, SHIFT P` | Toggle logging the current session (or pane) |
| ----------------- | -------------------------------------------- |
### Copy-Mode (Emacs)

| `Ctrl` `b`, `[`        | Enter copy mode       |
| ---------------------- | --------------------- |
| `Ctrl` `b`, `M-<`      | Bottom of history     |
| `Ctrl` `b`, `M->`      | Top of history        |
| `Ctrl` `b`, `M-m`      | Back to indentation   |
| `Ctrl` `b`, `M-w`      | Copy selection        |
| `Ctrl` `b`, `M-y`      | Paste selection       |
| `Ctrl` `b`, `Ctrl` `g` | Clear selection       |
| `Ctrl` `b`, `M-R`      | Cursor to top line    |
| `Ctrl` `b`, `M-r`      | Cursor to middle line |
| `Ctrl` `b`, `↑`        | Cursor Up             |
| `Ctrl` `b`, `↓`        | Cursor Down           |
| `Ctrl` `b`, `←`        | Cursor Left           |
| `Ctrl` `b`, `→`        | Cursor Right          |
### Copy-Mode (vi)

| `Ctrl` `b`, `[`     | Enter copy mode   |
| ------------------- | ----------------- |
| `Ctrl` `b`, `G`     | Bottom of history |
| `Ctrl` `b`, `g`     | Top of history    |
| `Ctrl` `b`, `Enter` | Copy selection    |
| `Ctrl` `b`, `p`     | Paste selection   |
| `Ctrl` `b`, `k`     | Cursor Up         |
| `Ctrl` `b`, `j`     | Cursor Down       |
| `Ctrl` `b`, `h`     | Cursor Left       |
| `Ctrl` `b`, `l`     | Cursor Right      |
## Plugins

Check out the complete [tmux plugins list](https://github.com/tmux-plugins/list) to see if others would fit nicely into your workflow. For more on Tmux, check out this excellent [video](https://www.youtube.com/watch?v=Lqehvpe_djs) by Ippsec and this [cheat sheet](https://mavericknerd.github.io/knowledgebase/ippsec/tmux/) based on the video.

- [tmux-sensible](https://github.com/tmux-plugins/tmux-sensible) - basic tmux settings everyone can agree on
- [Tmux logging](https://github.com/tmux-plugins/tmux-logging) - is an excellent choice for terminal logging
- [tmux-sessionist](https://github.com/tmux-plugins/tmux-sessionist) - Gives us the ability to manipulate Tmux sessions from within a session: switching to another session, creating a new named session, killing a session without detaching Tmux, promote the current pane to a new session, and more.
- [tmux-pain-control](https://github.com/tmux-plugins/tmux-pain-control) - A plugin for controlling panes and providing more intuitive key bindings for moving around, resizing, and splitting panes.
- [tmux-resurrect](https://github.com/tmux-plugins/tmux-resurrect) - This extremely handy plugin allows us to restore our Tmux environment after our host restarts. Some features include restoring all sessions, windows, panes, and their order, restoring running programs in a pane, restoring Vim sessions, and more.