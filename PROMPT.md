# General Instructions
I'd like you to fully autonomously reverse engineer this binary executable file. Copy the following checklist into file `task.md`, update it as you go, and DO NOT stop working until you're done and ready to issue a final report. Your primary goal is to name every function, parameter, and local variable visible in the Ghidra decompiler output. High-level understanding matters only insofar as it helps you produce correct names. As you discover broader conclusions about the binary, record them in `preliminary_conclusions.md`, but do not treat high-level summarization as a substitute for naming coverage.

# Checklist
[ ] Run `uv run scripts/create_ghidra_project.py <binary>` to create a Ghidra project and import the binary. This script defaults to creating `analysis-<first10ofsha256>/` in the current directory with project name `<first10ofsha256>`. Record the resulting project path and program name — all later Ghidra work depends on them.
[ ] Create an artifact directory for this run, for example `artifacts/<program-name>/`, and use it to store all intermediate analysis JSON produced by helper scripts and subagents.
[ ] Using `PyGhidra`, enumerate all functions in the file and capture the working function inventory in JSON so you can plan the analysis and split work into chunks. Ghidra is the source of truth for function existence and naming coverage.
[ ] Beginning at `main()` or the most credible entry dispatcher, make a first pass at reverse engineering the file, function-by-function. Apply high-confidence conclusions directly into the Ghidra project as you go: rename functions, rename parameters, rename local variables, apply recovered data types when they improve naming clarity, and add comments only when they help justify or preserve naming decisions.
[ ] Split the CFG into small, adjacent chunks of roughly equal complexity. Assign each chunk to a subagent using the following subagent instructions. You may have to go through this process several times to completely process the CFG.
* SUBAGENT INSTRUCTIONS: Reverse engineer the provided list of functions and write your conclusions to a JSON file in the run artifact directory. Do not write to Ghidra directly. Start from the current Ghidra state plus any synthesized JSON artifacts the main agent gives you. Explore the list of functions in graph order, breadth-first or depth-first, whichever is more appropriate. Generally, if a child function in the graph is simple or if understanding the child function is necessary to understand the parent, go depth-first. For each function you finish, emit the best supported function name plus the best supported parameter and local-variable names you can justify. Include summaries, annotations, and data-type suggestions only when they materially support those naming decisions.
[ ] After each wave of subagent work, synthesize their JSON outputs into a single reviewed artifact, resolve conflicts conservatively, and apply that artifact to Ghidra with `uv run scripts/apply_analysis_json_to_ghidra.py ...`.
[ ] Repeat the split, analyze, synthesize, and apply loop until EVERY SINGLE function, parameter, and local variable visible in the decompiler output has a confident human name recorded directly in Ghidra, except for any explicitly documented unknowns that remain genuinely irreducible.
[ ] ONLY once the Ghidra project has reached that naming coverage target: review the entirety of `preliminary_conclusions.md` and the final synthesized artifact to answer the higher-level questions. What is it trying to accomplish? What are the main components? How do the components fit together? Build a `report.md` that answers these questions and grounds the answers in specific named functions and variables.

# JSON Artifact Format
Subagents should write JSON shaped like:

```json
{
  "program_name": "optional-program-name",
  "functions": [
    {
      "address": "0x401000",
      "name": "proposed_function_name",
      "parameters": [
        {"ordinal": 0, "name": "ctx"}
      ],
      "locals": [
        {"current_name": "local_18", "name": "decoded_length"}
      ],
      "summary": "One or two sentence summary.",
      "annotations": [
        "Important observation or hypothesis.",
        "Another detail worth preserving."
      ]
    }
  ],
  "data_types": [
    {
      "kind": "struct",
      "name": "RecoveredType",
      "path": "/reaper",
      "size_bytes": 24,
      "fields": [
        {
          "offset": 0,
          "name": "field_0",
          "type": "uint32_t",
          "comment": "Optional field note."
        }
      ]
    }
  ]
}
```

The main agent may extend this format with additional reviewed fields before applying it to Ghidra, but subagents should stay within this structure unless the task clearly requires more detail. Function, parameter, and local naming fields take priority over every other field.

# Other Instructions
* Ghidra is the source of truth for analysis state and naming coverage. Do not create or rely on a database, `functions.md`, `working_notes.md`, or per-agent variants of those files.
* Annotations belong in Ghidra comments. When you synthesize subagent JSON, fold useful notes into function comments, plate comments, repeatable comments, or data-type field comments instead of storing them elsewhere.
* Before each task, ask yourself whether the task can be done by running code rather than by manual analysis. Prioritize writing global scripts that can be used to e.g. decrypt binary blobs or find function starts that tools fail to identify. Do NOT do manually any analysis that you can automate.
* Use Ghidra as your first pass for finding the list of functions and for decompiling each function. You can use `angr` for reverse engineering tasks that require advanced analysis. If you cannot get good results, or do not have high confidence in them, you can also use `r2` or Ghidra for a second opinion.
* If you encounter runtime construction of code, write custom logic to find any resulting functions and add them to Ghidra. If you encounter an embedded file, save it into the same Ghidra project and continue the analysis there.
* If you encounter any custom data structures, reverse engineer them and define the corresponding structs in Ghidra so the decompiler can use them.
* Read `CODEBASE.md` for an outline of the codebase.
* Do NOT jump to conclusions. Work slowly and deliberately: establish high-confidence facts about each function and variable, then build upward only as needed to improve naming accuracy.
