# PKA Score Inspector

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20x64-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

Drag a Cisco Packet Tracer activity (`.pka` / `.pkt`) onto the launcher and get:

- every graded check, its point value, and the expected answer
- the exact IOS commands that earn those points, per device
- PC / server IP, mask, and gateway settings
- the Simple PDU connectivity tests that award points
- a diff of what the answer config adds or removes

Everything is generated locally by deterministic Python. **No AI or LLM is used at runtime**, nothing is uploaded, and the activity file is never modified.

---

## Quick start

1. Download or clone this repository.
2. Double-click **`PKA-Score.cmd`**.
3. Pick your `.pka` or `.pkt` file in the window that opens.
4. The tool reads the activity and shows a summary, then asks what you want:

```text
  ----------------------------------------------------------------------------
  ACTIVITY LOADED
  ----------------------------------------------------------------------------
  File       LongTest3-Updated.pka  (409.1 KB)
  PT build   8.2.2.0400
  Grading    11,474 points across 11,387 checks
  Devices    6 need work, 2 already match

  ----------------------------------------------------------------------------
  WHAT DO YOU WANT TO SEE?
  ----------------------------------------------------------------------------

   1  Scoring criteria
      Every graded check, its point value, and the expected answer.

   2  Config commands
      IOS commands per device, with an explanation for each line.

   3  Everything  (recommended)
      Scoring criteria first, then the config commands.

   Q  Quit

  Choice [3]:
```

The window stays open after the report is printed, so you can read everything
and copy the commands. After a report, press **Enter** to quit or pick another
view of the same file.

You can also drag the activity file directly onto `PKA-Score.cmd` in Explorer;
it skips the picker and goes straight to the summary and menu.

---

## Requirements

| Requirement | Notes |
| --- | --- |
| Windows x64 | The vendored `libtwofish.dll` is a Windows x64 build. |
| Python 3.8+ | Install from [python.org](https://www.python.org/downloads/) and tick **Add python.exe to PATH**. |
| No pip packages | The tool uses only the Python standard library. |

Linux and macOS are possible with the upstream decoder, but this repository only ships the Windows DLL. See [jeamxn/cisco-pka-to-xml](https://github.com/jeamxn/cisco-pka-to-xml) if you want to build `libtwofish.so` / `libtwofish.dylib` yourself.

---

## What it writes

All output goes into one folder next to the activity, so nothing is scattered around:

```text
<activity>_report/
├── README.txt                      what the report contains
├── changes.txt                     answer-vs-start config diff
├── scoring/
│   ├── scoring_all.txt             every graded check (can be large)
│   └── scoring_key.txt             the checks that matter most
└── commands/
    ├── ALL_COMMANDS.txt            every device block in one paste-ready file
    ├── ALL_COMMANDS_EXPLAINED.txt  the same commands with a note above each one
    ├── <Device>.txt                one paste-ready block per device
    └── ENDPOINTS.txt               PC/server settings + graded PDU tests
```

Running the tool again only rewrites the section you chose, so you can view
the scoring criteria, return to the menu, and add the config commands without
losing the first report.

---

## How it works

1. **Decrypt** the activity with Twofish-EAX and zlib, using the same format
   Packet Tracer has used since PT 7.x. The decoder is vendored from
   [`jeamxn/cisco-pka-to-xml`](https://github.com/jeamxn/cisco-pka-to-xml).
2. **Read the grading tree** from the activity's `<COMPARISONS>` section. Every
   leaf node is one check with a point value and an expected value.
3. **Find the start and answer snapshots.** Activities store several
   running-config snapshots, and the order is not guaranteed. The tool scores
   each snapshot against the expected values in the grading tree: the snapshot
   with the fewest matches is the start, the one with the most matches is the
   answer. Ties go to the earliest snapshot for the start and the most
   complete one for the answer.
4. **Diff the configs** with a small IOS config parser and `difflib`. Only the
   lines the answer adds or changes are emitted, grouped under the correct
   interface / router block.
5. **Write the reports** and print the same information to the console.

There is no model, API key, prompt, or network call anywhere in the tool.
`difflib` and the config parser produce the commands.

---

## Command-line use

```bat
python pka_score.py activity.pka
python pka_score.py activity.pka --mode score
python pka_score.py activity.pka --mode commands --no-pause
python pka_score.py activity.pka --mode all --outdir C:\reports
```

| Option | Meaning |
| --- | --- |
| `--mode score` | Only the scoring criteria. |
| `--mode commands` | Only the config commands + endpoints. |
| `--mode all` | Both. |
| `--outdir DIR` | Put `<activity>_report` somewhere other than next to the file. |
| `--no-pause` | Skip the final Enter prompt (the menu still appears). |
| `--quiet` | Write the files without console output. |

If `--mode` is omitted, the interactive menu is shown. `--no-pause` only skips
the final Enter prompt; it does not skip the menu. With `--quiet` and no mode,
the tool writes everything without asking.

---

## Reading the scoring report

Each line looks like this:

```text
 2p [IP       ] Ports / Serial0/0/0 / IP Address   ->  10.10.10.5
```

- `2p` — the check is worth 2 points
- `[IP]` — grading category (`Physical`, `IP`, `Switching`, `Routing`, `ACL`, `NAT`, `Other`)
- `Ports / Serial0/0/0 / IP Address` — where the check lives
- `-> 10.10.10.5` — the expected value (the answer key)

Packet Tracer adds the points you earn and converts the total to a percentage,
so a 5-point check matters more than a 1-point check.

---

## Limitations

- The commands reproduce the **answer config stored in the activity**. If the
  instructor left an unusual value in the answer key (for example a default
  gateway that points at the device itself), the tool will reproduce it,
  because that is what Packet Tracer grades. Read the block before pasting.
- The tool targets config-line checks. Activities that also grade live
  protocol state (neighbor adjacency, convergence, STP elections) may need
  extra verification after the config is applied.
- Interface names and port numbers come from the file, so they match the
  topology, but always skim each block before pasting it.
- No `.pka` / `.pkt` files are included in this repository. Bring your own
  activity file.

---

## Privacy

- No network access at runtime.
- No telemetry, accounts, API keys, or cloud services.
- The activity file is opened read-only. The tool never writes to it.
- Generated reports stay on your machine.

---

## Credits

- [jeamxn/cisco-pka-to-xml](https://github.com/jeamxn/cisco-pka-to-xml) — MIT-licensed Packet Tracer decoder, vendored under `vendor/pka2xml/`.
- [mircodz/pka2xml](https://github.com/mircodz/pka2xml) — original documentation of the Packet Tracer file format.
- Niels Ferguson — Twofish reference C implementation.

See `vendor/pka2xml/NOTICE.md` for the third-party notice.

---

## License

MIT. See [LICENSE](LICENSE).

---

## Disclaimer

Use this tool only on activity files you are allowed to inspect. It does not
modify, submit, or unlock anything; it reads the grading data that is already
inside the file and prints it in a readable form.
