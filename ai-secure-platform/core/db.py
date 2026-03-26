import os
import logging
import datetime
from typing import Dict, Any, Optional
from motor.motor_asyncio import AsyncIOMotorClient

logger = logging.getLogger("asdip.db")

class Database:
    """
    Asynchronous MongoDB integration for ASDIP.
    """
    def __init__(self):
        self.uri = os.environ.get("MONGODB_URI", "mongodb://localhost:27017")
        self.db_name = os.environ.get("MONGODB_DB", "asdip")
        self.collection_name = os.environ.get("MONGODB_COLLECTION", "scans")
        self.usage_collection_name = "usage_analytics"
        self.client = None
        self.db = None
        self.collection = None
        self.usage_collection = None
        self.users_collection = None
        self.otp_collection = None

    async def connect(self):
        try:
            self.client = AsyncIOMotorClient(self.uri)
            self.db = self.client[self.db_name]
            self.collection = self.db[self.collection_name]
            self.usage_collection = self.db[self.usage_collection_name]
            self.users_collection = self.db["users"]
            self.otp_collection = self.db["otp_verification"]
            # Verify connection
            await self.client.admin.command('ping')
            
            # Optimization: Create Indexes
            await self.collection.create_index([("scan_id", 1)], unique=True)
            await self.collection.create_index([("timestamp", -1)])
            await self.collection.create_index([("tenant_id", 1)])
            await self.usage_collection.create_index([("timestamp", -1)])
            await self.users_collection.create_index("username", unique=True)
            await self.users_collection.create_index("email", unique=True)
            # OTP TTL index (5 minutes)
            await self.otp_collection.create_index("created_at", expireAfterSeconds=300)
            
            # Advanced: TTL Index for auto-cleanup (e.g., 30 days)
            await self.collection.create_index("timestamp", expireAfterSeconds=2592000)
            
            logger.info("Connected to MongoDB successfully with indexes.")
        except Exception as e:
            logger.error(f"MongoDB connection failed: {e}")
            self.client = None

    async def save_scan(self, scan_data: Dict[str, Any]) -> str:
        """Saves scan result to database."""
        if self.collection is None:
            await self.connect()
            if self.collection is None:
                logger.error("Database connection failed during save_scan.")
                raise Exception("Database not connected.")
            
        # Ensure timestamp and default tenant_id
        if "timestamp" not in scan_data:
            scan_data["timestamp"] = datetime.datetime.utcnow()
        if "tenant_id" not in scan_data:
            scan_data["tenant_id"] = "default"
            
        try:
            result = await self.collection.insert_one(scan_data)
            return str(result.inserted_id)
        except Exception as e:
            logger.error(f"Failed to save scan to DB: {e}")
            raise Exception(f"Database error: {e}")

    async def get_similar_threats(self, ip: str):
        if self.collection is None:
            await self.connect()
            if self.collection is None: return 0
        try:
            return await self.collection.count_documents({
                "suspicious_ips." + ip: {"$exists": True}
            })
        except:
            return 0

    async def get_risk_distribution(self):
        if self.collection is None:
            await self.connect()
            if self.collection is None: return []
        try:
            pipeline = [
                {"$group": {"_id": "$risk_level", "count": {"$sum": 1}}}
            ]
            return await self.collection.aggregate(pipeline).to_list(10)
        except Exception:
            return []

    # --- USER & OTP METHODS ---
    async def get_user_by_username(self, username: str) -> Optional[Dict]:
        if self.users_collection is None: await self.connect()
        return await self.users_collection.find_one({"username": username})

    async def get_user_by_email(self, email: str) -> Optional[Dict]:
        if self.users_collection is None: await self.connect()
        return await self.users_collection.find_one({"email": email})

    async def create_user(self, user_data: Dict[str, Any]):
        if self.users_collection is None: await self.connect()
        await self.users_collection.insert_one(user_data)

    async def save_otp(self, email: str, otp: str):
        if self.otp_collection is None: await self.connect()
        await self.otp_collection.update_one(
            {"email": email},
            {"$set": {"otp": otp, "created_at": datetime.datetime.utcnow()}},
            upsert=True
        )

    async def verify_otp(self, email: str, otp: str) -> bool:
        if self.otp_collection is None: await self.connect()
        record = await self.otp_collection.find_one({"email": email, "otp": otp})
        if record:
            await self.otp_collection.delete_one({"_id": record["_id"]})
            return True
        return False

    async def save_usage(self, usage_data: Dict[str, Any]):
        """Logs API usage analytics."""
        if self.usage_collection is None:
            await self.connect()
            if self.usage_collection is None:
                return
        try:
            await self.usage_collection.insert_one(usage_data)
        except Exception as e:
            logger.error(f"Failed to save usage analytics: {e}")

    async def get_usage_stats(self, tenant_id: str = "default") -> Dict[str, Any]:
        """Aggregation for usage metrics."""
        if self.usage_collection is None:
            await self.connect()
        try:
            query = {"tenant_id": tenant_id} if tenant_id != "system" else {}
            total = await self.usage_collection.count_documents(query)
            return {"total_api_calls": total}
        except Exception as e:
            logger.error(f"Failed to get usage stats: {e}")
            return {"total_api_calls": 0}

    async def get_recent_scans(self, limit: int = 10, tenant_id: str = "default") -> list:
        """Retrieve recent scans filtered by tenant."""
        if self.collection is None:
            await self.connect()
            if self.collection is None:
                return []
        
        try:
            query = {"tenant_id": tenant_id} if tenant_id != "system" else {}
            cursor = self.collection.find(query).sort("timestamp", -1).limit(limit)
            results = await cursor.to_list(length=limit)
            for res in results:
                res["_id"] = str(res["_id"])
            return results
        except Exception as e:
            logger.error(f"Failed to retrieve scans from DB for tenant {tenant_id}: {e}")
            return []

# Singleton instance
db = Database()
