ARG WAZUH_VERSION=4.14.9
FROM wazuh/wazuh-dashboard:${WAZUH_VERSION}

COPY --chown=wazuh-dashboard:wazuh-dashboard \
  wazuhGuardrail-2.19.6.zip /tmp/wazuhGuardrail-2.19.6.zip

USER wazuh-dashboard
RUN /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin install \
      file:///tmp/wazuhGuardrail-2.19.6.zip && \
    rm /tmp/wazuhGuardrail-2.19.6.zip
