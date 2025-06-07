# 🐉 DragonForceRansomWareYARA

This repository contains YARA rules generated from known DragonForce ransomware samples, collected from [MalwareBazaar](https://bazaar.abuse.ch/) in June 2025.

The rules were created using [yarGen](https://github.com/Neo23x0/yarGen) — a YARA rule generator developed by Florian Roth — to help identify and classify binaries associated with DragonForce ransomware operations.

---

## 📁 Repository Contents

- `dragonforce_raw.yar`  
  The initial YARA ruleset generated from 13 DragonForce ransomware samples. This ruleset includes all extracted string indicators, including common Windows APIs and DLLs.

- `dragonforce_clean.yar`  
  A cleaned YARA ruleset generated with the `--excludegood` flag. This version filters out generic strings found in benign software, reducing false positives and improving detection fidelity.

- `dragonforce_hashes.txt`  
  A list of SHA-256 file hashes for the DragonForce ransomware samples used to generate the rules. These hashes can be submitted to VirusTotal or other threat intel platforms for further analysis.

---

## 🧪 How the Rules Were Created

1. All ransomware PE (.exe) files tagged **DragonForce** were downloaded from [MalwareBazaar](https://bazaar.abuse.ch/).
2. Files were organized in:

   ```
   dragonforce_hashes.txt
   ```

3. Two YARA rulesets were generated using `yarGen`:

   ```bash
   # Full ruleset (including common APIs)
   dragonforce_raw.yar

   # Clean ruleset (excluding goodware-related strings)
   dragonforce_clean.yar
   ```

---

## 🧠 About DragonForce

DragonForce began as a pro-Palestine hacktivist group in 2023, later transitioning into a financially motivated ransomware operation. The group has been associated with high-profile attacks and employs tactics such as phishing, red team frameworks, and double extortion ransomware deployment.

More information is available in the [associated blog post](https://peterstollery.co.uk).

---

## 📌 Usage

These rules are intended for:

- Threat hunting
- Malware triage
- Incident response
- Sandboxing and sample classification

They can be used with tools like:

- YARA CLI
- VirusTotal Intelligence
- Hybrid Analysis / Triage
- AnyRun
- Cuckoo Sandbox

---

## 📄 License

These rules are shared under the [MIT License](LICENSE) and are intended for research and educational use only. Attribution appreciated.

---

## 📬 Contact

For feedback, contributions, or questions, feel free to reach out via GitHub Issues or open a pull request.
