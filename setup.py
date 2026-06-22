from setuptools import setup, find_packages

setup(
    name="dfx-mcp-scanner",
    version="0.1.0",
    description="Security scanner for MCP (Model Context Protocol) servers.",
    long_description=open("README.md", encoding="utf-8").read() if __import__("os").path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    license="MIT",
    python_requires=">=3.10",
    packages=find_packages(),
    install_requires=["click>=8.1", "rich>=13.0", "pydantic>=2.0", "pyyaml>=6.0"],
    extras_require={"dev": ["pytest>=7.0", "pytest-cov", "ruff"]},
    entry_points={"console_scripts": ["mcp-scanner=mcp_scanner.cli:main"]},
    author="Dockfix Labs",
    author_email="security@dockfixlabs.dev",
    url="https://github.com/dockfixlabs/mcp-scanner",
)
