import os
import subprocess
import datetime
import json

class CICDPipeline:
    def __init__(self):
        self.project_name = "VAST Project"
        self.build_number = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.results = {
            'build_number': self.build_number,
            'timestamp': datetime.datetime.now().isoformat(),
            'stages': {}
        }

    def log_stage(self, stage_name, success, message=""):
        """Log the result of a pipeline stage"""
        self.results['stages'][stage_name] = {
            'success': success,
            'message': message,
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        status = "✅ PASSED" if success else "❌ FAILED"
        print(f"{status} - {stage_name}: {message}")

    def stage_code_checkout(self):
        """Verify Django project structure"""
        print(f"\n📁 STAGE 1: Code Checkout & Structure")
        print("-" * 40)
        
        required_files = ['manage.py', 'requirements.txt', 'Dockerfile']
        missing_files = [f for f in required_files if not os.path.exists(f)]
        
        if not missing_files:
            self.log_stage("Code Checkout", True, f"All required files present: {required_files}")
            return True
        else:
            self.log_stage("Code Checkout", False, f"Missing files: {missing_files}")
            return False

    def stage_dependency_check(self):
        """Check Python dependencies"""
        print(f"\n📦 STAGE 2: Dependency Validation")
        print("-" * 40)
        
        try:
            result = subprocess.run(["pip", "check"], capture_output=True, text=True)
            if result.returncode == 0:
                self.log_stage("Dependency Check", True, "All dependencies compatible")
                return True
            else:
                self.log_stage("Dependency Check", False, f"Dependency conflicts: {result.stderr}")
                return False
        except Exception as e:
            self.log_stage("Dependency Check", False, str(e))
            return False

    def stage_security_scan(self):
        """Enhanced security scanning for Railway deployment"""
        print(f"\n🔒 STAGE 3: Security & Configuration Scan")
        print("-" * 40)
        
        security_issues = []
        
        try:
            # Check main settings
            settings_files = ['vast_project/settings.py', 'vast_project/railway_settings.py']
            
            for settings_file in settings_files:
                if os.path.exists(settings_file):
                    with open(settings_file, 'r') as f:
                        content = f.read()
                    
                    if "DEBUG = True" in content and "railway_settings" in settings_file:
                        security_issues.append(f"DEBUG mode enabled in {settings_file}")
                    
                    if "SECRET_KEY = 'django-insecure-" in content:
                        security_issues.append(f"Default insecure secret key in {settings_file}")
            
            # Check for Railway-specific configurations
            if os.path.exists('vast_project/railway_settings.py'):
                with open('vast_project/railway_settings.py', 'r') as f:
                    content = f.read()
                    if 'dj_database_url' not in content:
                        security_issues.append("Missing Railway database configuration")
            
            if security_issues:
                message = f"Found {len(security_issues)} security issues: {', '.join(security_issues)}"
                self.log_stage("Security Scan", False, message)
                return False
            else:
                self.log_stage("Security Scan", True, "No security issues detected")
                return True
                
        except Exception as e:
            self.log_stage("Security Scan", False, f"Scan error: {e}")
            return False

    def stage_railway_readiness(self):
        """Check Railway deployment readiness"""
        print(f"\n🚂 STAGE 4: Railway Deployment Readiness")
        print("-" * 40)
        
        try:
            # Check Django settings for Railway
            result = subprocess.run(
                ["python", "-c", "from vast_project import railway_settings; print('Railway settings OK')"],
                capture_output=True, text=True
            )
            
            if result.returncode == 0:
                self.log_stage("Railway Readiness", True, "Railway configuration valid")
                return True
            else:
                self.log_stage("Railway Readiness", False, f"Railway config error: {result.stderr}")
                return False
                
        except Exception as e:
            self.log_stage("Railway Readiness", False, str(e))
            return False

    def generate_report(self):
        """Generate a comprehensive pipeline report"""
        print(f"\n📊 CI/CD PIPELINE REPORT")
        print("=" * 60)
        print(f"Project: {self.project_name}")
        print(f"Build Number: {self.build_number}")
        print(f"Timestamp: {self.results['timestamp']}")
        print("-" * 60)
        
        total_stages = len(self.results['stages'])
        passed_stages = sum(1 for stage in self.results['stages'].values() if stage['success'])
        
        for stage_name, stage_data in self.results['stages'].items():
            status = "✅ PASSED" if stage_data['success'] else "❌ FAILED"
            print(f"{status} {stage_name}: {stage_data['message']}")
        
        print("-" * 60)
        print(f"Overall Result: {passed_stages}/{total_stages} stages passed")
        
        if passed_stages == total_stages:
            print("🎉 CI/CD PIPELINE SUCCEEDED!")
        else:
            print("💥 CI/CD PIPELINE FAILED!")
        
        # Save report to file
        with open(f'pipeline_report_{self.build_number}.json', 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"📄 Detailed report saved to: pipeline_report_{self.build_number}.json")

    def run_pipeline(self):
        """Execute the full CI/CD pipeline"""
        print(f"🏁 STARTING CI/CD PIPELINE FOR {self.project_name}")
        print("=" * 60)
        
        stages = [
            self.stage_code_checkout,
            self.stage_dependency_check,
            self.stage_security_scan,
            self.stage_railway_readiness
        ]
        
        for stage in stages:
            if not stage():
                print(f"\n💥 Pipeline failed at stage: {stage.__name__}")
                break
        
        self.generate_report()

if __name__ == "__main__":
    pipeline = CICDPipeline()
    pipeline.run_pipeline()
