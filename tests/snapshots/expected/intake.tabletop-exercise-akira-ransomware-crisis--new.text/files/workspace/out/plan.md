{
  "base": "cb490ae99a16b3ea43d9d804d62e0ab11988a596",
  "blocking": 0,
  "body": "Closes #2\n\nEntry `scenarios/ransomware/akira`, from a platform export.\n\nLeft to complete or review:\n- [ ] `scenarios/ransomware/akira/scenario.yaml` `/version`: `default 1.0.0: give this entry's version, the next one for a new version`\n- [ ] `scenarios/ransomware/akira/scenario.yaml` `/status`: `default VERIFIED: review it before the pull request`\n- [ ] `scenarios/ransomware/akira/scenario.yaml` `/requires/openaev`: `default: the platform version the built-in contracts were recorded on; give the oldest version the scenario works on`\n- [ ] `scenarios/ransomware/akira/scenario.yaml` `/requires/edition`: `default CE: give EE if the scenario needs the Enterprise Edition`\n- [ ] `scenarios/ransomware/akira/CHANGELOG.md` ``: `a starting section for this version: say what it holds before the pull request`\n\nFiles:\n- `scenarios/ransomware/akira/CHANGELOG.md` `c5f2e74a1e852337a5bb79fab2798db97be358f14c376bf256ebe348770bf853`\n- `scenarios/ransomware/akira/README.md` `a36d0497ea9adb794db8c5d70a283974af64c133447c8bad1054d0b60dd4c2a8`\n- `scenarios/ransomware/akira/scenario.json` `d50a46f3f054788ff8a98b5c88ee11e7d0e2c83dfcb84caaf76c59ba0059f346`\n- `scenarios/ransomware/akira/scenario.yaml` `52787a13d476dc0eb3baa60a763b4b9d7a815823726360942f30b65584ba0ae2`\n",
  "changed": true,
  "entry": "scenarios/ransomware/akira",
  "files": [
    {
      "path": "scenarios/ransomware/akira/CHANGELOG.md",
      "sha256": "c5f2e74a1e852337a5bb79fab2798db97be358f14c376bf256ebe348770bf853"
    },
    {
      "path": "scenarios/ransomware/akira/README.md",
      "sha256": "a36d0497ea9adb794db8c5d70a283974af64c133447c8bad1054d0b60dd4c2a8"
    },
    {
      "path": "scenarios/ransomware/akira/scenario.json",
      "sha256": "d50a46f3f054788ff8a98b5c88ee11e7d0e2c83dfcb84caaf76c59ba0059f346"
    },
    {
      "path": "scenarios/ransomware/akira/scenario.yaml",
      "sha256": "52787a13d476dc0eb3baa60a763b4b9d7a815823726360942f30b65584ba0ae2"
    }
  ],
  "mode": "new",
  "title": "feat(scenarios): add akira (#2)"
}
