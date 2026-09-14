//! OpenAPI 3.0 specification and Swagger UI handler for IndraMQTT management API.

/// Returns the OpenAPI 3.0.3 specification in JSON format.
pub fn openapi_spec_json() -> &'static str {
    r#"{
  "openapi": "3.0.3",
  "info": {
    "title": "IndraMQTT Management API",
    "description": "High-performance hybrid MQTT 5.0 broker with streaming SQL engine (185 functions), decentralized SWIM gossip clustering, and zero-allocation connector pipelines.",
    "version": "1.0.0",
    "contact": {
      "name": "IndraMQTT Engineering",
      "url": "https://github.com/ankur-paan/indramqtt"
    },
    "license": {
      "name": "MIT OR Apache-2.0"
    }
  },
  "servers": [
    {
      "url": "http://localhost:8081",
      "description": "Local IndraMQTT Node"
    }
  ],
  "tags": [
    { "name": "Cluster & Nodes", "description": "Cluster topology, node health, and run-queues" },
    { "name": "Clients & Sessions", "description": "Connected MQTT 3.1.1 / 5.0 client sessions" },
    { "name": "Observability", "description": "Live throughput, latency, and Prometheus metrics" },
    { "name": "Rule Engine", "description": "Streaming SQL rules and analytical functions" },
    { "name": "Data Connectors", "description": "External data sinks (Kafka, Postgres, Redis, MySQL, S3)" },
    { "name": "Authentication & ACL", "description": "User credential management and topic ACL rules" }
  ],
  "paths": {
    "/healthz": {
      "get": {
        "tags": ["Cluster & Nodes"],
        "summary": "Node health check",
        "operationId": "healthCheck",
        "responses": {
          "200": {
            "description": "Node is healthy and operating normally",
            "content": {
              "text/plain": {
                "schema": { "type": "string", "example": "OK" }
              }
            }
          }
        }
      }
    },
    "/api/v1/nodes": {
      "get": {
        "tags": ["Cluster & Nodes"],
        "summary": "Get cluster node status and metrics",
        "operationId": "getNodes",
        "responses": {
          "200": {
            "description": "Cluster node list",
            "content": {
              "application/json": {
                "schema": {
                  "type": "array",
                  "items": {
                    "type": "object",
                    "properties": {
                      "node": { "type": "string", "example": "indramqtt@node-01" },
                      "status": { "type": "string", "example": "running" },
                      "version": { "type": "string", "example": "0.1.0" },
                      "connections": { "type": "integer", "example": 1420 },
                      "uptime_seconds": { "type": "integer", "example": 86400 }
                    }
                  }
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/metrics": {
      "get": {
        "tags": ["Observability"],
        "summary": "Get broker metrics",
        "operationId": "getMetrics",
        "responses": {
          "200": {
            "description": "Prometheus text format metrics or JSON counters",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "messages_received": { "type": "integer", "example": 128400 },
                    "messages_sent": { "type": "integer", "example": 256800 },
                    "active_connections": { "type": "integer", "example": 1420 },
                    "subscriptions_count": { "type": "integer", "example": 3840 }
                  }
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/clients": {
      "get": {
        "tags": ["Clients & Sessions"],
        "summary": "List active client sessions",
        "operationId": "listClients",
        "parameters": [
          {
            "name": "limit",
            "in": "query",
            "description": "Maximum number of clients to return",
            "schema": { "type": "integer", "default": 100 }
          }
        ],
        "responses": {
          "200": {
            "description": "Array of connected client identifiers",
            "content": {
              "application/json": {
                "schema": {
                  "type": "array",
                  "items": { "type": "string", "example": "sensor-arm-01" }
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/clients/{id}": {
      "get": {
        "tags": ["Clients & Sessions"],
        "summary": "Get detailed client session information",
        "operationId": "getClientDetail",
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "description": "Client ID",
            "schema": { "type": "string" }
          }
        ],
        "responses": {
          "200": {
            "description": "Client session details",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "client_id": { "type": "string", "example": "sensor-arm-01" },
                    "connected": { "type": "boolean", "example": true },
                    "clean_session": { "type": "boolean", "example": false },
                    "subscriptions": {
                      "type": "array",
                      "items": { "type": "string", "example": "factory/+/temp" }
                    },
                    "queued_messages": { "type": "integer", "example": 0 }
                  }
                }
              }
            }
          },
          "404": { "description": "Client not found" }
        }
      }
    },
    "/api/v1/auth/users": {
      "get": {
        "tags": ["Authentication & ACL"],
        "summary": "List all configured users and quotas",
        "operationId": "listUsers",
        "responses": {
          "200": {
            "description": "List of users with quota allocations",
            "content": {
              "application/json": {
                "schema": {
                  "type": "array",
                  "items": {
                    "type": "object",
                    "properties": {
                      "username": { "type": "string", "example": "factory_user" },
                      "max_connections": { "type": "integer", "example": 100 },
                      "max_inflight": { "type": "integer", "example": 64 },
                      "max_publish_rate": { "type": "number", "example": 500.0 }
                    }
                  }
                }
              }
            }
          }
        }
      },
      "post": {
        "tags": ["Authentication & ACL"],
        "summary": "Create or update user credentials and quotas",
        "operationId": "createUser",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["username", "password"],
                "properties": {
                  "username": { "type": "string", "example": "factory_user" },
                  "password": { "type": "string", "example": "SecretPass123!" },
                  "max_connections": { "type": "integer", "example": 100 },
                  "max_inflight": { "type": "integer", "example": 64 },
                  "max_publish_rate": { "type": "number", "example": 500.0 }
                }
              }
            }
          }
        },
        "responses": {
          "200": { "description": "User created or updated successfully" },
          "400": { "description": "Invalid input payload" }
        }
      }
    },
    "/api/v1/auth/acls": {
      "get": {
        "tags": ["Authentication & ACL"],
        "summary": "List ordered ACL rules",
        "operationId": "listAcls",
        "responses": {
          "200": {
            "description": "List of ACL rules evaluated in order",
            "content": {
              "application/json": {
                "schema": {
                  "type": "array",
                  "items": {
                    "type": "object",
                    "properties": {
                      "client_pattern": { "type": "string", "example": "sensor-*" },
                      "action": { "type": "string", "enum": ["publish", "subscribe", "all"], "example": "publish" },
                      "topic_pattern": { "type": "string", "example": "sensors/+" },
                      "allow": { "type": "boolean", "example": true }
                    }
                  }
                }
              }
            }
          }
        }
      },
      "post": {
        "tags": ["Authentication & ACL"],
        "summary": "Add new ACL rule",
        "operationId": "createAcl",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["client_pattern", "action", "topic_pattern", "allow"],
                "properties": {
                  "client_pattern": { "type": "string", "example": "sensor-*" },
                  "action": { "type": "string", "enum": ["publish", "subscribe", "all"], "example": "publish" },
                  "topic_pattern": { "type": "string", "example": "sensors/+" },
                  "allow": { "type": "boolean", "example": true }
                }
              }
            }
          }
        },
        "responses": {
          "200": { "description": "ACL rule registered" }
        }
      }
    },
    "/api/v1/rules": {
      "get": {
        "tags": ["Rule Engine"],
        "summary": "List all streaming SQL rules",
        "operationId": "listRules",
        "responses": {
          "200": {
            "description": "Array of configured rules",
            "content": {
              "application/json": {
                "schema": {
                  "type": "array",
                  "items": {
                    "type": "object",
                    "properties": {
                      "id": { "type": "string", "example": "rule-1" },
                      "name": { "type": "string", "example": "high-temp-alert" },
                      "topic_filter": { "type": "string", "example": "sensors/+" },
                      "sql_query": { "type": "string", "example": "SELECT temperature FROM \"sensors/+\" WHERE temperature > 40.0" },
                      "enabled": { "type": "boolean", "example": true }
                    }
                  }
                }
              }
            }
          }
        }
      },
      "post": {
        "tags": ["Rule Engine"],
        "summary": "Create new streaming SQL rule",
        "operationId": "createRule",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["name", "topic_filter"],
                "properties": {
                  "name": { "type": "string", "example": "high-temp-alert" },
                  "topic_filter": { "type": "string", "example": "sensors/+" },
                  "sql_query": { "type": "string", "example": "SELECT temperature FROM \"sensors/+\" WHERE temperature > 40.0" },
                  "enabled": { "type": "boolean", "default": true }
                }
              }
            }
          }
        },
        "responses": {
          "200": { "description": "Rule created" }
        }
      }
    },
    "/api/v1/rules/test": {
      "post": {
        "tags": ["Rule Engine"],
        "summary": "Test streaming SQL query against mock payload",
        "operationId": "testRule",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["sql_query", "topic", "payload"],
                "properties": {
                  "sql_query": { "type": "string", "example": "SELECT temperature, math:sqrt(temperature) AS sqrt_val FROM \"sensors/+\" WHERE temperature > 30.0" },
                  "topic": { "type": "string", "example": "sensors/kitchen" },
                  "payload": { "type": "string", "example": "{\"temperature\": 45.2, \"pressure\": 101.3}" }
                }
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Rule test evaluation result",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "matched": { "type": "boolean", "example": true },
                    "output": { "type": "string", "example": "{\"sqrt_val\":6.723,\"temperature\":45.2}" }
                  }
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/rules/functions": {
      "get": {
        "tags": ["Rule Engine"],
        "summary": "List catalog of 185 analytical SQL functions",
        "operationId": "listFunctions",
        "responses": {
          "200": {
            "description": "Catalog of supported streaming functions",
            "content": {
              "application/json": {
                "schema": {
                  "type": "array",
                  "items": { "type": "string", "example": "math:sqrt" }
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/rules/{id}": {
      "get": {
        "tags": ["Rule Engine"],
        "summary": "Get rule by ID",
        "operationId": "getRule",
        "parameters": [
          { "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }
        ],
        "responses": {
          "200": { "description": "Rule details" },
          "404": { "description": "Rule not found" }
        }
      },
      "delete": {
        "tags": ["Rule Engine"],
        "summary": "Delete rule by ID",
        "operationId": "deleteRule",
        "parameters": [
          { "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }
        ],
        "responses": {
          "200": { "description": "Rule deleted" },
          "404": { "description": "Rule not found" }
        }
      }
    },
    "/api/v1/connectors": {
      "get": {
        "tags": ["Data Connectors"],
        "summary": "List registered data connectors",
        "operationId": "listConnectors",
        "responses": {
          "200": {
            "description": "List of active connectors",
            "content": {
              "application/json": {
                "schema": {
                  "type": "array",
                  "items": {
                    "type": "object",
                    "properties": {
                      "id": { "type": "string", "example": "conn-kafka-prod" },
                      "connector_type": { "type": "string", "example": "kafka" },
                      "status": { "type": "string", "example": "connected" }
                    }
                  }
                }
              }
            }
          }
        }
      },
      "post": {
        "tags": ["Data Connectors"],
        "summary": "Register new data connector",
        "operationId": "createConnector",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["connector_type", "config"],
                "properties": {
                  "connector_type": { "type": "string", "example": "kafka" },
                  "config": { "type": "object" }
                }
              }
            }
          }
        },
        "responses": {
          "200": { "description": "Connector registered" }
        }
      }
    }
  }
}"#
}

/// Standalone Swagger UI HTML that points to `/api-docs/openapi.json`.
pub fn swagger_ui_html() -> &'static str {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>IndraMQTT - Interactive Swagger API Explorer</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
  <style>
    body {
      margin: 0;
      background: #0d1117;
      color: #e6edf3;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }
    .topbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 12px 24px;
      background: #161b22;
      border-bottom: 1px solid #30363d;
    }
    .topbar h1 {
      margin: 0;
      font-size: 18px;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .topbar a {
      color: #58a6ff;
      text-decoration: none;
      font-size: 14px;
    }
    .topbar a:hover {
      text-decoration: underline;
    }
    .swagger-ui {
      filter: invert(88%) hue-rotate(180deg);
    }
    .swagger-ui .topbar { display: none !important; }
  </style>
</head>
<body>
  <div class="topbar">
    <h1>
      <span>⚡</span> IndraMQTT OpenAPI 3.0 Interactive Explorer
    </h1>
    <div>
      <a href="/dashboard">← Back to Management Dashboard</a>
    </div>
  </div>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.onload = () => {
      window.ui = SwaggerUIBundle({
        url: '/api-docs/openapi.json',
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIBundle.SwaggerUIStandalonePreset
        ],
        layout: "BaseLayout"
      });
    };
  </script>
</body>
</html>"#
}
