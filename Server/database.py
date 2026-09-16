from prisma import Prisma

db = Prisma()

async def get_db():
    """Dependency to get database instance"""
    return db
