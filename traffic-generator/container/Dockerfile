# Project A traffic generator (ap-trafficgen). Built with --network none from a pinned local base image; nothing is
# downloaded. Only the engine, the profile adapters, the Project A profile and the entrypoint are copied (no Control
# Center, no tests, no Project B config, no credentials, no certificates).
ARG BASE
FROM ${BASE}
USER root
COPY simulator/f5_ai_workload_sim.py simulator/sim_profiles.py simulator/sim_transport.py simulator/mcp_adapter.py /opt/trafficgen/simulator/
COPY simulator/profiles/project-a.json /opt/trafficgen/simulator/profiles/project-a.json
COPY container/trafficgen_entry.py /opt/trafficgen/trafficgen_entry.py
RUN chmod -R a=rX /opt/trafficgen \
 && python -B -c "import boto3, botocore, ssl, http.client, json" \
 && python -B -c "import sys; sys.path.insert(0, '/opt/trafficgen/simulator'); import sim_profiles; sim_profiles.load('/opt/trafficgen/simulator/profiles/project-a.json')"
USER 65534:65534
WORKDIR /opt/trafficgen/simulator
LABEL org.f5lab.component="ap-trafficgen" org.f5lab.environment="project-a"
ENTRYPOINT ["python", "-B", "/opt/trafficgen/trafficgen_entry.py"]
