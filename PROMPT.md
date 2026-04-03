# General Instructions
I'd like you to fully autonomously reverse engineer this binary executable file. Copy the following checklist into file `task.md`, update it as you go, and DO NOT stop working until you're done and ready to issue a final report. Your goal is to incrementally increase your understanding of the binary, as represented by named functions and variables in the Ghidra decompilation. Don't stop until you have a total understanding of the binary: what is it trying to accomplish? What are the main components? How do the components fit together? As you discover the high-level answers to these questions, record your preliminary conclusions in `preliminary_conclusions.md`.

# Checklist
[ ] Run `uv run scripts/create_ghidra_project.py <binary>` to create a Ghidra project and import the binary. This script defaults to creating `analysis-<first10ofsha256>/` in the current directory with project name `<first10ofsha256>`. Record the resulting project path and program name — all later Ghidra work depends on them.
[ ] Create an artifact directory for this run, for example `artifacts/<program-name>/`, and use it to store all intermediate analysis JSON produced by helper scripts and subagents.
[ ] Using `PyGhidra`, enumerate all functions in the file and capture the working function inventory in JSON so you can plan the analysis and split work into chunks. Ghidra is the source of truth for function existence and naming.
[ ] Beginning at `main()` or the most credible entry dispatcher, make a first pass at reverse engineering the file, function-by-function. Apply high-confidence conclusions directly into the Ghidra project as you go: rename functions, rename parameters and locals, apply recovered data types, and add comments summarizing behavior and important annotations.
[ ] Split the CFG into small, adjacent chunks of roughly equal complexity. Assign each chunk to a subagent using the following subagent instructions. You may have to go through this process several times to completely process the CFG.
* SUBAGENT INSTRUCTIONS: Reverse engineer the provided list of functions and write your conclusions to a JSON file in the run artifact directory. Do not write to Ghidra directly. Start from the current Ghidra state plus any synthesized JSON artifacts the main agent gives you. Explore the list of functions in graph order, breadth-first or depth-first, whichever is more appropriate. Generally, if a child function in the graph is simple or if understanding the child function is necessary to understand the parent, go depth-first. For each function you finish, emit the best supported name, a short summary, optional annotations, and any recovered parameter, local-variable, or data-type suggestions you can justify.
[ ] After each wave of subagent work, synthesize their JSON outputs into a single reviewed artifact, resolve conflicts conservatively, and apply that artifact to Ghidra with `uv run scripts/apply_analysis_json_to_ghidra.py ...`.
[ ] Repeat the split, analyze, synthesize, and apply loop until EVERY SINGLE function in the file has a confident conclusion recorded directly in Ghidra.
[ ] ONLY once the Ghidra project contains confident conclusions on EVERY SINGLE function in the file: review the entirety of `preliminary_conclusions.md` and the final synthesized artifact to answer our high-level questions. What is it trying to accomplish? What are the main components? How do the components fit together? Build a `report.md` that answers these questions and grounds the answers in specific functions.

# JSON Artifact Format
Subagents should write JSON shaped like:

```json
{
  "program_name": "optional-program-name",
  "functions": [
    {
      "address": "0x401000",
      "name": "proposed_function_name",
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

The main agent may extend this format with additional reviewed fields before applying it to Ghidra, but subagents should stay within this structure unless the task clearly requires more detail.

# Other Instructions
* Ghidra is the source of truth for analysis state. Do not create or rely on a database, `functions.md`, `working_notes.md`, or per-agent variants of those files.
* Annotations belong in Ghidra comments. When you synthesize subagent JSON, fold useful notes into function comments, plate comments, repeatable comments, or data-type field comments instead of storing them elsewhere.
* Before each task, ask yourself whether the task can be done by running code rather than by manual analysis. Prioritize writing global scripts that can be used to e.g. decrypt binary blobs or find function starts that tools fail to identify. Do NOT do manually any analysis that you can automate.
* Use Ghidra as your first pass for finding the list of functions and for decompiling each function. You can use `angr` for reverse engineering tasks that require advanced analysis. If you cannot get good results, or do not have high confidence in them, you can also use `r2` or Ghidra for a second opinion.
* If you encounter runtime construction of code, write custom logic to find any resulting functions and add them to Ghidra. If you encounter an embedded file, save it into the same Ghidra project and continue the analysis there.
* If you encounter any custom data structures, reverse engineer them and define the corresponding structs in Ghidra so the decompiler can use them.
* Read `CODEBASE.md` for an outline of the codebase.
* Do NOT jump to conclusions. Work slowly and deliberately: establish high-confidence facts about the binary and build into higher-level conclusions.
