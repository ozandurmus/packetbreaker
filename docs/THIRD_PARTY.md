# Third-party components

PacketBreaker uses dependencies rather than copying code from the reference repositories.
- React and React DOM — MIT: https://github.com/facebook/react
- React Flow (@xyflow/react) — MIT: https://github.com/xyflow/xyflow
- Apache ECharts and zrender — Apache-2.0 / BSD-3-Clause: https://github.com/apache/echarts
- FastAPI — MIT: https://github.com/fastapi/fastapi
- Uvicorn — BSD-3-Clause: https://github.com/encode/uvicorn
- DuckDB — MIT: https://github.com/duckdb/duckdb
- NumPy — BSD-3-Clause: https://github.com/numpy/numpy
- Wireshark/tshark — GPL-2.0-or-later, installed separately, not bundled: https://www.wireshark.org/

Frontend dependency license notices are retained in the generated JavaScript bundle.
The npm lockfile records transitive dependencies. Python dependencies are installed
by pip from their own distributions, which retain their license metadata.
