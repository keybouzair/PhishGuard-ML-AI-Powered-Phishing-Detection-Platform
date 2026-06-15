"""
API Documentation and Swagger/OpenAPI Integration
"""

from flask import Blueprint, jsonify, render_template_string
import json

api_docs = Blueprint('api_docs', __name__)

# OpenAPI Specification
OPENAPI_SPEC = {
    "openapi": "3.0.3",
    "info": {
        "title": "Phishing Detection API",
        "description": """
# Phishing Detection API

Advanced API for detecting phishing websites using machine learning and threat intelligence.

## Features
- Real-time URL analysis
- Threat intelligence integration
- User management
- Activity logging
- Webhook support

## Authentication
Most endpoints require authentication. Use one of the following methods:
- **Session-based**: Login via `/user_login` or `/admin_login`
- **API Key**: Include `X-API-Key` header with your API key

## Rate Limiting
- Standard users: 100 requests per minute
- API key users: Based on key configuration
- Rate limit headers are included in responses
        """,
        "version": "2.0.0",
        "contact": {
            "name": "API Support",
            "email": "support@phishingdetector.com"
        },
        "license": {
            "name": "MIT",
            "url": "https://opensource.org/licenses/MIT"
        }
    },
    "servers": [
        {
            "url": "http://localhost:5000",
            "description": "Development server"
        },
        {
            "url": "https://api.phishingdetector.com",
            "description": "Production server"
        }
    ],
    "tags": [
        {"name": "URL Analysis", "description": "URL checking and analysis endpoints"},
        {"name": "Threat Intelligence", "description": "External threat intelligence integration"},
        {"name": "Users", "description": "User management endpoints"},
        {"name": "Blocklist", "description": "URL blocklist management"},
        {"name": "Analytics", "description": "Statistics and reporting"},
        {"name": "Webhooks", "description": "Webhook management"},
        {"name": "Authentication", "description": "Authentication endpoints"}
    ],
    "paths": {
        "/api/check_url": {
            "post": {
                "tags": ["URL Analysis"],
                "summary": "Check URL for phishing",
                "description": "Analyzes a URL using machine learning to determine if it's a phishing attempt",
                "operationId": "checkUrl",
                "security": [{"sessionAuth": []}, {"apiKey": []}],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["url"],
                                "properties": {
                                    "url": {
                                        "type": "string",
                                        "format": "uri",
                                        "example": "https://suspicious-site.com/login"
                                    }
                                }
                            }
                        }
                    }
                },
                "responses": {
                    "200": {
                        "description": "URL analysis result",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/URLCheckResult"}
                            }
                        }
                    },
                    "400": {"description": "Invalid request"},
                    "401": {"description": "Authentication required"},
                    "429": {"description": "Rate limit exceeded"}
                }
            }
        },
        "/api/check_url_advanced": {
            "post": {
                "tags": ["URL Analysis"],
                "summary": "Advanced URL analysis",
                "description": "Comprehensive URL analysis including threat intelligence, typosquatting detection, and explainability",
                "operationId": "checkUrlAdvanced",
                "security": [{"sessionAuth": []}, {"apiKey": []}],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["url"],
                                "properties": {
                                    "url": {"type": "string", "format": "uri"},
                                    "include_threat_intel": {"type": "boolean", "default": True},
                                    "include_explanation": {"type": "boolean", "default": True}
                                }
                            }
                        }
                    }
                },
                "responses": {
                    "200": {
                        "description": "Comprehensive analysis result",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/AdvancedURLCheckResult"}
                            }
                        }
                    }
                }
            }
        },
        "/api/threat_intel/{url}": {
            "get": {
                "tags": ["Threat Intelligence"],
                "summary": "Get threat intelligence for URL",
                "description": "Query external threat intelligence sources for URL",
                "operationId": "getThreatIntel",
                "security": [{"apiKey": []}],
                "parameters": [
                    {
                        "name": "url",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"}
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Threat intelligence data",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ThreatIntelResult"}
                            }
                        }
                    }
                }
            }
        },
        "/api/stats": {
            "get": {
                "tags": ["Analytics"],
                "summary": "Get statistics",
                "description": "Get user or global statistics based on role",
                "operationId": "getStats",
                "security": [{"sessionAuth": []}, {"apiKey": []}],
                "responses": {
                    "200": {
                        "description": "Statistics data",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Statistics"}
                            }
                        }
                    }
                }
            }
        },
        "/api/history": {
            "get": {
                "tags": ["Analytics"],
                "summary": "Get URL check history",
                "description": "Get history of URL checks",
                "operationId": "getHistory",
                "security": [{"sessionAuth": []}, {"apiKey": []}],
                "parameters": [
                    {
                        "name": "limit",
                        "in": "query",
                        "schema": {"type": "integer", "default": 50}
                    }
                ],
                "responses": {
                    "200": {
                        "description": "URL check history",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/History"}
                            }
                        }
                    }
                }
            }
        },
        "/api/analytics/dashboard": {
            "get": {
                "tags": ["Analytics"],
                "summary": "Get dashboard analytics",
                "description": "Comprehensive analytics data for dashboard",
                "operationId": "getDashboardAnalytics",
                "security": [{"sessionAuth": []}, {"apiKey": []}],
                "responses": {
                    "200": {
                        "description": "Dashboard analytics data",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/DashboardAnalytics"}
                            }
                        }
                    }
                }
            }
        },
        "/api/report/generate": {
            "post": {
                "tags": ["Analytics"],
                "summary": "Generate report",
                "description": "Generate a report in various formats",
                "operationId": "generateReport",
                "security": [{"sessionAuth": []}, {"apiKey": []}],
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "format": {
                                        "type": "string",
                                        "enum": ["json", "csv", "html", "pdf"]
                                    },
                                    "start_date": {"type": "string", "format": "date"},
                                    "end_date": {"type": "string", "format": "date"}
                                }
                            }
                        }
                    }
                },
                "responses": {
                    "200": {"description": "Generated report"}
                }
            }
        },
        "/get_blocklist": {
            "get": {
                "tags": ["Blocklist"],
                "summary": "Get blocklist",
                "description": "Get all blocked URLs",
                "operationId": "getBlocklist",
                "responses": {
                    "200": {
                        "description": "Blocklist data",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Blocklist"}
                            }
                        }
                    }
                }
            }
        },
        "/api/blocklist/add": {
            "post": {
                "tags": ["Blocklist"],
                "summary": "Add URL to blocklist",
                "description": "Add a URL to the blocklist (admin only)",
                "operationId": "addToBlocklist",
                "security": [{"sessionAuth": []}],
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["url"],
                                "properties": {
                                    "url": {"type": "string"},
                                    "reason": {"type": "string"}
                                }
                            }
                        }
                    }
                },
                "responses": {
                    "200": {"description": "URL added to blocklist"},
                    "403": {"description": "Admin access required"}
                }
            }
        },
        "/api/users": {
            "get": {
                "tags": ["Users"],
                "summary": "Get all users",
                "description": "Get list of all users (admin only)",
                "operationId": "getUsers",
                "security": [{"sessionAuth": []}],
                "responses": {
                    "200": {
                        "description": "List of users",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/UserList"}
                            }
                        }
                    },
                    "403": {"description": "Admin access required"}
                }
            }
        },
        "/api/users/add": {
            "post": {
                "tags": ["Users"],
                "summary": "Add new user",
                "description": "Create a new user account (admin only)",
                "operationId": "addUser",
                "security": [{"sessionAuth": []}],
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/NewUser"}
                        }
                    }
                },
                "responses": {
                    "200": {"description": "User created"},
                    "400": {"description": "Invalid request"},
                    "403": {"description": "Admin access required"}
                }
            }
        },
        "/api/webhooks": {
            "get": {
                "tags": ["Webhooks"],
                "summary": "Get webhooks",
                "description": "Get all configured webhooks",
                "operationId": "getWebhooks",
                "security": [{"sessionAuth": []}],
                "responses": {
                    "200": {
                        "description": "List of webhooks",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/WebhookList"}
                            }
                        }
                    }
                }
            },
            "post": {
                "tags": ["Webhooks"],
                "summary": "Register webhook",
                "description": "Register a new webhook endpoint",
                "operationId": "registerWebhook",
                "security": [{"sessionAuth": []}],
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/NewWebhook"}
                        }
                    }
                },
                "responses": {
                    "200": {"description": "Webhook registered"}
                }
            }
        },
        "/api/keys": {
            "get": {
                "tags": ["Authentication"],
                "summary": "Get API keys",
                "description": "Get user's API keys",
                "operationId": "getApiKeys",
                "security": [{"sessionAuth": []}],
                "responses": {
                    "200": {
                        "description": "List of API keys",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ApiKeyList"}
                            }
                        }
                    }
                }
            },
            "post": {
                "tags": ["Authentication"],
                "summary": "Generate API key",
                "description": "Generate a new API key",
                "operationId": "generateApiKey",
                "security": [{"sessionAuth": []}],
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["name"],
                                "properties": {
                                    "name": {"type": "string"},
                                    "permissions": {
                                        "type": "array",
                                        "items": {"type": "string"}
                                    },
                                    "expires_days": {"type": "integer"}
                                }
                            }
                        }
                    }
                },
                "responses": {
                    "200": {
                        "description": "API key generated (only shown once)",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/NewApiKey"}
                            }
                        }
                    }
                }
            }
        }
    },
    "components": {
        "securitySchemes": {
            "sessionAuth": {
                "type": "apiKey",
                "in": "cookie",
                "name": "session"
            },
            "apiKey": {
                "type": "apiKey",
                "in": "header",
                "name": "X-API-Key"
            }
        },
        "schemas": {
            "URLCheckResult": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "prediction_label": {"type": "string", "enum": ["Safe", "Unsafe"]},
                    "prediction_score": {"type": "number"},
                    "is_phishing": {"type": "boolean"},
                    "blocklisted": {"type": "boolean"}
                }
            },
            "AdvancedURLCheckResult": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "prediction": {"$ref": "#/components/schemas/URLCheckResult"},
                    "threat_intelligence": {"$ref": "#/components/schemas/ThreatIntelResult"},
                    "typosquatting": {
                        "type": "object",
                        "properties": {
                            "is_typosquatting": {"type": "boolean"},
                            "similar_to": {"type": "string"},
                            "similarity_score": {"type": "number"}
                        }
                    },
                    "explanation": {
                        "type": "object",
                        "properties": {
                            "contributing_factors": {"type": "array"},
                            "recommendations": {"type": "array"}
                        }
                    },
                    "final_risk_score": {"type": "number"},
                    "risk_level": {"type": "string"}
                }
            },
            "ThreatIntelResult": {
                "type": "object",
                "properties": {
                    "threat_score": {"type": "number"},
                    "is_malicious": {"type": "boolean"},
                    "threat_level": {"type": "string"},
                    "sources": {
                        "type": "object",
                        "properties": {
                            "virustotal": {"type": "object"},
                            "google_safe_browsing": {"type": "object"},
                            "urlhaus": {"type": "object"}
                        }
                    }
                }
            },
            "Statistics": {
                "type": "object",
                "properties": {
                    "total_urls": {"type": "integer"},
                    "safe_urls": {"type": "integer"},
                    "unsafe_urls": {"type": "integer"},
                    "detection_rate": {"type": "number"}
                }
            },
            "History": {
                "type": "object",
                "properties": {
                    "history": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "url": {"type": "string"},
                                "prediction_label": {"type": "string"},
                                "prediction_score": {"type": "number"},
                                "checked_at": {"type": "string"}
                            }
                        }
                    },
                    "count": {"type": "integer"}
                }
            },
            "DashboardAnalytics": {
                "type": "object",
                "properties": {
                    "time_series": {"type": "array"},
                    "hourly_distribution": {"type": "object"},
                    "top_phishing": {"type": "array"},
                    "keywords": {"type": "object"},
                    "geographic": {"type": "object"}
                }
            },
            "Blocklist": {
                "type": "object",
                "properties": {
                    "urls": {"type": "array"},
                    "count": {"type": "integer"}
                }
            },
            "UserList": {
                "type": "object",
                "properties": {
                    "users": {
                        "type": "array",
                        "items": {"$ref": "#/components/schemas/User"}
                    }
                }
            },
            "User": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "username": {"type": "string"},
                    "email": {"type": "string"},
                    "role": {"type": "string"},
                    "is_active": {"type": "boolean"}
                }
            },
            "NewUser": {
                "type": "object",
                "required": ["username", "password"],
                "properties": {
                    "username": {"type": "string"},
                    "password": {"type": "string"},
                    "email": {"type": "string"}
                }
            },
            "WebhookList": {
                "type": "object",
                "properties": {
                    "webhooks": {"type": "array"}
                }
            },
            "NewWebhook": {
                "type": "object",
                "required": ["name", "url", "events"],
                "properties": {
                    "name": {"type": "string"},
                    "url": {"type": "string"},
                    "events": {"type": "array"},
                    "secret": {"type": "string"}
                }
            },
            "ApiKeyList": {
                "type": "object",
                "properties": {
                    "keys": {"type": "array"}
                }
            },
            "NewApiKey": {
                "type": "object",
                "properties": {
                    "key": {"type": "string", "description": "Only shown once!"},
                    "key_id": {"type": "integer"},
                    "name": {"type": "string"},
                    "permissions": {"type": "array"}
                }
            }
        }
    }
}


@api_docs.route('/api/docs')
def swagger_ui():
    """Serve Swagger UI"""
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Phishing Detection API - Documentation</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
    <style>
        body { margin: 0; padding: 0; }
        .swagger-ui .topbar { display: none; }
        .swagger-ui .info { margin: 20px 0; }
        .swagger-ui .info .title { color: #333; }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
        SwaggerUIBundle({
            url: "/api/openapi.json",
            dom_id: '#swagger-ui',
            presets: [
                SwaggerUIBundle.presets.apis,
                SwaggerUIBundle.SwaggerUIStandalonePreset
            ],
            layout: "BaseLayout",
            deepLinking: true,
            showExtensions: true,
            showCommonExtensions: true
        });
    </script>
</body>
</html>
    ''')


@api_docs.route('/api/openapi.json')
def openapi_spec():
    """Serve OpenAPI specification"""
    return jsonify(OPENAPI_SPEC)


@api_docs.route('/api/redoc')
def redoc():
    """Serve ReDoc documentation"""
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Phishing Detection API - Documentation</title>
    <link href="https://fonts.googleapis.com/css?family=Montserrat:300,400,700|Roboto:300,400,700" rel="stylesheet">
    <style>
        body { margin: 0; padding: 0; }
    </style>
</head>
<body>
    <redoc spec-url="/api/openapi.json"></redoc>
    <script src="https://cdn.jsdelivr.net/npm/redoc/bundles/redoc.standalone.js"></script>
</body>
</html>
    ''')
