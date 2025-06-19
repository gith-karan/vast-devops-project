import os
import subprocess
import sys
import time

def run_command(command, description):
    """Run a command and print the result"""
    print(f"\n{'='*50}")
    print(f"RUNNING: {description}")
    print(f"COMMAND: {command}")
    print(f"{'='*50}")
    
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ SUCCESS: {description}")
            if result.stdout:
                print(f"OUTPUT: {result.stdout}")
        else:
            print(f"❌ ERROR: {description}")
            print(f"ERROR OUTPUT: {result.stderr}")
        return result.returncode == 0
    except Exception as e:
        print(f"❌ EXCEPTION: {e}")
        return False

def deploy_application():
    """Simulate a deployment pipeline"""
    print("🚀 STARTING DEPLOYMENT PIPELINE FOR VAST PROJECT")
    print("="*60)
    
    # Step 1: Check Python version
    if not run_command("python --version", "Checking Python Version"):
        return False
    
    # Step 2: Install/Update dependencies
    if not run_command("pip install -r requirements.txt", "Installing Dependencies"):
        return False
    
    # Step 3: Run database migrations
    if not run_command("python manage.py makemigrations", "Creating Migrations"):
        print("⚠️  No new migrations needed")
    
    if not run_command("python manage.py migrate", "Running Database Migrations"):
        return False
    
    # Step 4: Collect static files
    if not run_command("python manage.py collectstatic --noinput", "Collecting Static Files"):
        print("⚠️  Static files collection had issues, continuing...")
    
    # Step 5: Run tests (if any exist)
    run_command("python manage.py test", "Running Tests")
    
    # Step 6: Check if server can start
    print("\n🔍 TESTING SERVER STARTUP...")
    print("This will start the server for 10 seconds to test if it works...")
    
    # Start server in background and test
    server_process = subprocess.Popen(
        ["python", "manage.py", "runserver", "127.0.0.1:8000"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # Wait a bit for server to start
    time.sleep(3)
    
    # Test health endpoint
    try:
        import requests
        response = requests.get("http://127.0.0.1:8000/health/", timeout=5)
        if response.status_code == 200:
            print("✅ Health check passed!")
            print(f"Response: {response.json()}")
        else:
            print(f"⚠️  Health check returned status: {response.status_code}")
    except Exception as e:
        print(f"⚠️  Health check failed: {e}")
    
    # Stop the server
    server_process.terminate()
    
    print("\n🎉 DEPLOYMENT PIPELINE COMPLETED!")
    print("="*60)
    return True

if __name__ == "__main__":
    deploy_application()
