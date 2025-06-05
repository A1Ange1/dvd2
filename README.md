# dvd2

**dvd2** is a professional DLL Injector designed for efficiency, flexibility, and reliability.  
Created and maintained by [@A1Ange1](https://github.com/A1Ange1).

---

## 🚀 Overview

dvd2 provides advanced DLL (Dynamic-Link Library) injection capabilities for testing, research, and development purposes.  
**For ethical and educational use only.**

---

## 🎯 Features

- **DLL Injection Capabilities**
  - Classic (LoadLibrary) DLL injection
  - Manual Mapping (stub/POC implementation)
  - Reflective injection (stub/POC implementation)
  - Choose injection method per operation

- **Process Management**
  - Process enumeration with search/filter capability
  - Per-process details tooltips
  - Add/remove favorite processes
  - UI updates for favorites and recent DLLs

- **Recent and Favorite Management**
  - Maintains a list of recently injected DLLs
  - Maintains a list of favorite process IDs
  - Persists recent DLLs and favorites in configuration

- **Logging & Configuration**
  - Action/event logging to file or Windows Registry
  - Loads and saves configuration to file or registry
  - Logging can be enabled/disabled via settings

- **User Interface**
  - GUI dialogs: Main window, Settings, and About
  - Tooltips and user feedback throughout
  - Tray icon and minimize-to-tray support
  - Timer-based process list refresh for up-to-date info

- **Command-Line Interface (CLI)**
  - Run injections or dry runs directly from the command line
  - Supports all major injection features via CLI

---

## 🛠️ Getting Started

### ✅ Cloning the Repository

```bash
git clone https://github.com/A1Ange1/dvd2.git
cd dvd2
```

### ✅ Building (with MinGW/g++)

**You must compile the resource file (.rc) and link it:**

```sh
windres resource.rc -O coff -o resource.res
g++ dvd2.cpp resource.res -o dvd2.exe -lshlwapi -lcomdlg32 -mconsole
```

- `-mconsole` ensures CLI output appears in the console.

---

## 🖥️ Usage

### **Graphical User Interface (GUI)**

- Run `dvd2.exe` with **no arguments** to launch the GUI.
- Use the GUI to:
  - Browse/select a DLL and target process
  - Choose injection method
  - Adjust settings (config storage, logging, tray icon, etc.)
  - View About dialog for credits and features
- The GUI stores recent DLLs and favorite processes for easy access.

### **Command-Line Interface (CLI)**

- Run `dvd2.exe` with arguments to use the CLI mode.
- The GUI will not appear if CLI arguments are present.

#### **Syntax:**

```sh
dvd2.exe /pid <PID> /dll <full_path_to_dll> [/method <0|1|2>] [/dryrun]
```

- `/pid <PID>` — Target process ID (required)
- `/dll <DLL path>` — Full path to DLL to inject (required)
- `/method <0|1|2>` — Injection method:  
    `0 = Classic (LoadLibrary)`  
    `1 = Manual Mapping (POC)`  
    `2 = Reflective (POC)`  
    (Default: 0)
- `/dryrun` — Simulate the injection without performing it (optional)

#### **Examples:**

Classic injection:
```sh
dvd2.exe /pid 1234 /dll "C:\path\to\test.dll"
```

Manual mapping (stub, simulated):
```sh
dvd2.exe /pid 1234 /dll "C:\path\to\test.dll" /method 1
```

Dry run (no actual injection performed):
```sh
dvd2.exe /pid 1234 /dll "C:\path\to\test.dll" /dryrun
```

#### **CLI Output:**

- `Injection SUCCESS` — Injection (or dry run) completed successfully.
- `Injection FAILED: <reason>` — Injection failed; reason is shown.

---

## ⚠️ Rules & Contribution Guidelines

- **For ethical research and education only.**  
  Do not use for unauthorized or malicious activity.
- **Respect all applicable laws and regulations.**
- **Open issues before submitting large changes.**
- **Write clear, maintainable code with comments where appropriate.**
- **No spam, irrelevant, or malicious PRs/issues.**

---

## 📞 Contact

Maintained by [A1Ange1](https://github.com/A1Ange1).  
For questions or to get in touch, open an issue or reach out on Telegram: [t.me/Real4yu](https://t.me/Real4yu)

---

## 📝 License

Licensed by The Unlicense.  
See the [LICENSE](./LICENSE) file for details.

> **Disclaimer:**  
> This project is intended for educational and authorized testing purposes only.  
> The creator is not responsible for any misuse.
