# AI_SAST · *AI‑Powered Static Application Security Testing*

> **AI_SAST** is a container‑native security scanner that uses OpenAI's GPT-4o models to analyze multiple projects for security vulnerabilities, providing **detailed vulnerability reports** for all your codebases.

## ✨ Key Features

|  |  |
|---|---|
| 🤖 **GPT-4o Powered** | Leverages OpenAI's most capable model for deep, context-aware security analysis |
| 📂 **Multi-Project Support** | Batch process multiple project directories in a single run |
| 💰 **Cost Tracking** | Real-time tracking of token usage and costs for transparency |
| 🔄 **Context-Aware Analysis** | Maps file dependencies to understand data‑flows and taint sources |
| 🔍 **Smart File Discovery** | Automatically filters security‑relevant files from large codebases |
| 🤝 **CodeQL Integration** | Combines findings from GitHub's CodeQL with GPT-4o analysis |
| 📊 **Visualization** | Web dashboard for tracking scan progress and viewing results |
| 🐳 **Docker Support** | Single command to launch and process all your projects |

---

## 📚 Table of Contents

- [Quick Start](#-quick-start)
- [Project Structure](#-project-structure)
- [Web Interface](#-web-interface)
- [Output Format](#-output-format)
- [Pricing](#-pricing)
- [Example Usage](#-example-usage)

---

## 🚀 Quick Start

### Requirements

* **Docker 20.10+**
* Access to **OpenAI API** with GPT-4o model access

```bash
# Pull & launch the container
docker run -d \
  --name ai_sast \
  -p 5000:5000 \
  -v /path/to/your/projects:/project/input \
  -v /path/to/output:/project/output \
  andreimoldovan2/ai_sast:latest
```

Open http://localhost:5000 in your browser to access the web interface.

## 📁 Project Structure

The tool expects the following directory structure:

```
/project/
├── input/
│   ├── project1/
│   │   ├── src/
│   │   ├── ...
│   ├── project2/
│   │   ├── src/
│   │   ├── ...
│   └── ...
└── output/
    ├── project1/
    ├── project2/
    └── ...
```

- All projects should be placed in subdirectories under `/project/input/`
- Results will be generated in matching subdirectories under `/project/output/`

## 🌐 Web Interface

The web interface provides the following features:

1. **API Key Setup**: Enter your OpenAI API key once at startup
2. **Project Overview**: View all projects in the input directory
3. **Scan Execution**: Start scans for all projects with one click
4. **Progress Tracking**: Monitor scan progress and token usage in real-time
5. **Results Viewing**: Explore vulnerabilities with severity ratings and recommendations
6. **Cost Tracking**: Track token usage and costs in real-time

## 📝 Output Format

For each project, the tool generates:

- JSON vulnerability reports for each type of vulnerability
- A summary JSON file with all findings
- Token usage and cost statistics

## 💰 Pricing

This tool uses OpenAI's GPT-4o with the following pricing:

- **Input**: $3.750 per 1M tokens
- **Output**: $15.000 per 1M tokens

The web interface displays real-time cost tracking to help manage expenses.

## 🔍 Example Usage

1. Place your project directories in `/project/input/`
2. Start the container with the Docker command above
3. Open http://localhost:5000 in your browser
4. Enter your OpenAI API key when prompted
5. Click "Start Scan" to analyze all projects
6. View results in the web interface or in `/project/output/`

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
