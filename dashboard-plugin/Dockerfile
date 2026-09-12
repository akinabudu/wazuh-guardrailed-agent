ARG WAZUH_VERSION=4.9.2
FROM wazuh/wazuh-dashboard:${WAZUH_VERSION}

COPY --chown=wazuh-dashboard:wazuh-dashboard \
  wazuhGuardrail-2.13.0.zip /tmp/wazuhGuardrail-2.13.0.zip

USER wazuh-dashboard
RUN /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin install \
      file:///tmp/wazuhGuardrail-2.13.0.zip && \
    rm /tmp/wazuhGuardrail-2.13.0.zip
