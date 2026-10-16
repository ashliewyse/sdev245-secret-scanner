# One-minute Secret Scanner recording

**Status: the actual recording is still required.** Record the program really executing; this guide alone is not the video.

Before recording, run python create_demo.py once to generate the fake examples locally. Existing files are kept. Open PowerShell in the project folder. Increase the text size until commands and results are readable. Use the fake demo files only. If python is unavailable, use the bundled interpreter described in the README.

| Time | Action and suggested narration |
| --- | --- |
| 0–10 seconds | Run help. “This Python CLI scans files and folders for seven types of possible exposed credentials.” |
| 10–25 seconds | Scan the fake file. “These invented examples produce one finding for each detector.” |
| 25–40 seconds | Scan the folder. “Directory scanning also finds the nested example. Each result includes a filename, line number, rule, and matched string.” |
| 40–55 seconds | Show redacted JSON. “JSON supports structured reporting. Redaction hides matched strings; logs stay separate on stderr.” |
| 55–60 seconds | Point out the summary. “Eight findings across three files. The scanner never validates credentials online.” |

Commands, in order:

~~~powershell
python scanner.py --help
python scanner.py demo/fake-secrets.txt
python scanner.py demo
python scanner.py demo --format json --redact
~~~

The last command has a longer report; scroll to show one finding and the summary. Exit code 1 means findings were detected, as expected here.

Use your normal screen recorder to capture approximately 60 seconds. Review playback for readable results and real execution. Save a video file, or a shareable recording link your instructor can access. Keep unrelated tabs and private material out of the capture.

Before submitting, review the GitHub code link, README, and actual video. Canvas has not been submitted by this project preparation.
