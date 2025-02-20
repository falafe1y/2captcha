#!/usr/bin/env python3

import asyncio

CMD = [
    "./client",
    "login",
    "password",
    "https://target_site.com"
]

async def run_client():
    process = await asyncio.create_subprocess_exec(
        *CMD,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await process.communicate()
    
    if stdout:
        print(f"Output: {stdout.decode().strip()}")
    if stderr:
        print(f"Error: {stderr.decode().strip()}")

async def main():
    tasks = [run_client() for _ in range(10)]
    await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main())

