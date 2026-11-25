"""
This kubernetes worker template runs an asynchronous event loop that processes firing alerts pushed into a Redis queue. When an alert targeting an unhealthy telemetry component matches, it patches the deployment's spec.template.metadata.annotations with a fresh restartedAt timestamp, triggering a standard rolling update.
"""

import asyncio
import datetime
import json
import logging
from fastapi import FastAPI, Request, BackgroundTasks, Response
from kubernetes_asyncio import client, config
from kubernetes_asyncio.client.exceptions import ApiException
import redis.asyncio as aioredis

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("remediator")

app = FastAPI(title="Telemetry Automation Remediation Worker")

REDIS_URL = "redis://redis-service.monitoring.svc.cluster.local:6379/0"
QUEUE_NAME = "remediation_alerts"
NAMESPACE = "monitoring"

redis_client = None

@app.on_event("startup")
async def startup_event():
    global redis_client
    # Initialize in-cluster Kubernetes config
    try:
        config.load_incluster_config()
        logger.info("Loaded in-cluster Kubernetes configuration.")
    except Exception as e:
        logger.warning(f"Failed to load in-cluster config, falling back to local kubeconfig: {e}")
        await config.load_kube_config()
    
    # Initialize Async Redis Connection
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    # Start background queue consumer loop
    asyncio.create_task(redis_queue_consumer())

@app.post("/alerts")
async def receive_alertmanager_webhook(request: Request, background_tasks: BackgroundTasks):
    """
    Ingest payload from Alertmanager webhook and enqueue for async handling
    """
    payload = await request.json()
    logger.info(f"Received webhook payload with {len(payload.get('alerts', []))} alerts.")
    
    for alert in payload.get("alerts", []):
        if alert.get("status") == "firing":
            alert_data = {
                "alertname": alert["labels"].get("alertname"),
                "deployment": alert["labels"].get("deployment"),
                "timestamp": datetime.datetime.utcnow().isoformat()
            }
            background_tasks.add_task(enqueue_remediation, alert_data)
            
    return Response(status_code=202)

async def enqueue_remediation(alert_data: dict):
    await redis_client.rpush(QUEUE_NAME, json.dumps(alert_data))
    logger.info(f"Enqueued alert for remediation: {alert_data['alertname']}")

async def redis_queue_consumer():
    """
    Continuous worker loop consuming from Redis and managing K8s rollout restarts
    """
    async with client.ApiClient() as api_client:
        apps_v1 = client.AppsV1Api(api_client)
        
        while True:
            try:
                # Async blocking pop from Redis queue
                result = await redis_client.blpop(QUEUE_NAME, timeout=5)
                if not result:
                    continue
                
                _, raw_data = result
                alert = json.loads(raw_data)
                deployment_name = alert.get("deployment")
                
                if not deployment_name:
                    logger.warning("Alert payload missing 'deployment' label. Skipping.")
                    continue
                
                logger.info(f"Processing rollout restart for deployment: {deployment_name}")
                await trigger_rollout_restart(apps_v1, deployment_name)
                
            except Exception as e:
                logger.error(f"Error in consumer loop loop: {e}")
                await asyncio.sleep(2)

async def trigger_rollout_restart(apps_v1: client.AppsV1Api, deployment_name: str):
    """
    Executes an asynchronous rollout restart by updating deployment annotations
    """
    now = datetime.datetime.utcnow().isoformat() + "Z"
    restart_patch = {
        "spec": {
            "template": {
                "metadata": {
                    "annotations": {
                        "kubectl.kubernetes.io/restartedAt": now
                    }
                }
            }
        }
    }
    try:
        await apps_v1.patch_namespaced_deployment(
            name=deployment_name,
            namespace=NAMESPACE,
            body=restart_patch
        )
        logger.info(f"Successfully triggered rolling update for {deployment_name}.")
    except ApiException as e:
        logger.error(f"Kubernetes API Exception when restarting {deployment_name}: {e}")
