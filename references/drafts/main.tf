# ==============================================================================
# 1. PROVIDER & INITIALIZATION CONFIGURATIONS
# ==============================================================================
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.30"
    }
  }
}

provider "local" {}

# Assumes your agent runs on the desktop plane pointing to your active kubeconfig
provider "kubernetes" {
  config_path = "~/.kube/config"
}

# ==============================================================================
# 2. ANSIBLE INVENTORY HANDOFF GENERATION (Ensuring Thread Consistency)
# ==============================================================================
resource "local_file" "ansible_inventory" {
  content = templatefile("${path.module}/inventory.tmpl", {
    node_1_name  = "pi-01"
    node_1_ip    = "100.100.1.11"
    node_2_name  = "pi-02"
    node_2_ip    = "100.100.1.12"
    node_3_name  = "pi-03"
    node_3_ip    = "100.100.1.13"
    desktop_name = "workstation"
    desktop_ip   = "127.0.0.1"
  })
  filename = "${path.module}/inventory.ini"
}

# ==============================================================================
# 3. KUBERNETES NAMESPACE INITIALIZATION
# ==============================================================================
resource "kubernetes_namespace" "monitoring" {
  metadata {
    name = "monitoring"
  }
}

# ==============================================================================
# 4. GRAFANA STORAGE (Desktop Control Plane Topology)
# ==============================================================================
resource "kubernetes_persistent_volume" "grafana" {
  metadata {
    name = "pv-grafana"
    labels = {
      app       = "telemetry"
      component = "grafana"
    }
  }
  spec {
    capacity = {
      storage = "10Gi"
    }
    volume_mode                      = "Filesystem"
    access_modes                     = ["ReadWriteOnce"]
    persistent_volume_reclaim_policy = "Retain"
    storage_class_name               = "telemetry-local-storage"
    
    persistent_volume_source {
      local {
        path = "/var/lib/k8s/main-storage/grafana"
      }
    }
    node_affinity {
      required {
        node_selector_term {
          match_expressions {
            key      = "kubernetes.io/hostname"
            operator = "In"
            values   = ["workstation"]
          }
        }
      }
    }
  }
}

resource "kubernetes_persistent_volume_claim" "grafana" {
  metadata {
    name      = "pvc-grafana"
    namespace = kubernetes_namespace.monitoring.metadata[0].name
  }
  spec {
    access_modes       = ["ReadWriteOnce"]
    storage_class_name = "telemetry-local-storage"
    resources {
      requests = {
        storage = "10Gi"
      }
    }
    selector {
      match_labels = {
        component = "grafana"
      }
    }
  }
}

# ==============================================================================
# 5. LOKI STORAGE (Distributed Edge Topology - pi-01)
# ==============================================================================
resource "kubernetes_persistent_volume" "loki_pi_01" {
  metadata {
    name = "pv-loki-pi-01"
    labels = {
      app       = "telemetry"
      component = "loki"
      node      = "pi-01"
    }
  }
  spec {
    capacity = {
      storage = "30Gi"
    }
    volume_mode                      = "Filesystem"
    access_modes                     = ["ReadWriteOnce"]
    persistent_volume_reclaim_policy = "Retain"
    storage_class_name               = "telemetry-local-storage"
    
    persistent_volume_source {
      local {
        path = "/opt/k8s/edge-storage/loki"
      }
    }
    node_affinity {
      required {
        node_selector_term {
          match_expressions {
            key      = "kubernetes.io/hostname"
            operator = "In"
            values   = ["pi-01"]
          }
        }
      }
    }
  }
}

resource "kubernetes_persistent_volume_claim" "loki_pi_01" {
  metadata {
    name      = "pvc-loki-pi-01"
    namespace = kubernetes_namespace.monitoring.metadata[0].name
  }
  spec {
    access_modes       = ["ReadWriteOnce"]
    storage_class_name = "telemetry-local-storage"
    resources {
      requests = {
        storage = "30Gi"
      }
    }
    selector {
      match_labels = {
        component = "loki"
        node      = "pi-01"
      }
    }
  }
}

# ==============================================================================
# 6. PROMETHEUS STORAGE (Distributed Edge Topology - pi-02)
# ==============================================================================
resource "kubernetes_persistent_volume" "prometheus_pi_02" {
  metadata {
    name = "pv-prometheus-pi-02"
    labels = {
      app       = "telemetry"
      component = "prometheus"
      node      = "pi-02"
    }
  }
  spec {
    capacity = {
      storage = "40Gi"
    }
    volume_mode                      = "Filesystem"
    access_modes                     = ["ReadWriteOnce"]
    persistent_volume_reclaim_policy = "Retain"
    storage_class_name               = "telemetry-local-storage"
    
    persistent_volume_source {
      local {
        path = "/opt/k8s/edge-storage/prometheus"
      }
    }
    node_affinity {
      required {
        node_selector_term {
          match_expressions {
            key      = "kubernetes.io/hostname"
            operator = "In"
            values   = ["pi-02"]
          }
        }
      }
    }
  }
}

resource "kubernetes_persistent_volume_claim" "prometheus_pi_02" {
  metadata {
    name      = "pvc-prometheus-pi-02"
    namespace = kubernetes_namespace.monitoring.metadata[0].name
  }
  spec {
    access_modes       = ["ReadWriteOnce"]
    storage_class_name = "telemetry-local-storage"
    resources {
      requests = {
        storage = "40Gi"
      }
    }
    selector {
      match_labels = {
        component = "prometheus"
        node      = "pi-02"
      }
    }
  }
}

# ==============================================================================
# 7. AUTOMATION AGENT RBAC CONFIGURATIONS (Namespace-Scoped)
# ==============================================================================

# Dedicated identity for your Python remediation/automation worker
resource "kubernetes_service_account" "automation_agent" {
  metadata {
    name      = "automation-agent-sa"
    namespace = kubernetes_namespace.monitoring.metadata.name
    labels = {
      app       = "telemetry"
      component = "automation-worker"
    }
  }
}

# Granular, least-privilege permissions required to manipulate pods and collection endpoints
resource "kubernetes_role" "automation_agent" {
  metadata {
    name      = "automation-agent-role"
    namespace = kubernetes_namespace.monitoring.metadata.name
  }

  # Core API Group: Managing target endpoints and tracking/wiping broken pods
  rule {
    api_groups = [""]
    resources  = ["pods", "pods/log", "endpoints", "services"]
    verbs      = ["get", "list", "watch", "delete", "create", "update", "patch"]
  }

  # Apps API Group: Allows programmatic rollout restarts on telemetry deployments
  rule {
    api_groups = ["apps"]
    resources  = ["deployments", "statefulsets", "daemonsets"]
    verbs      = ["get", "list", "watch", "update", "patch"]
  }
}

# Bind the ServiceAccount identity to the prescriptive Automation Role
resource "kubernetes_role_binding" "automation_agent" {
  metadata {
    name      = "automation-agent-rolebinding"
    namespace = kubernetes_namespace.monitoring.metadata.name
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Role"
    name      = kubernetes_role.automation_agent.metadata[0].name
  }

  subject {
    kind      = "ServiceAccount"
    name      = kubernetes_service_account.automation_agent.metadata[0].name
    namespace = kubernetes_namespace.monitoring.metadata.name
  }
}

# ==============================================================================
# 8. OUTPUTS FOR DOWNSTREAM AGENT PIPELINES
# ==============================================================================
output "automation_service_account_name" {
  description = "The ServiceAccount name for the async automation container."
  value       = kubernetes_service_account.automation_agent.metadata[0].name
}

output "monitoring_namespace_name" {
  description = "The operational telemetry namespace."
  value       = kubernetes_namespace.monitoring.metadata.name
}
