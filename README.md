# Daily Snyk Security Issues Report - GitHub Action

This GitHub Action runs daily at 9:00 AM EST to fetch critical, high, and medium severity issues from your Snyk organization and sends notifications to Slack.

## Features

- **Daily Automated Reports**: Runs every day at 9:00 AM EST
- **Issue Severity Tracking**: Fetches critical, high, and medium severity issues
- **Slack Notifications**: Sends formatted reports to your Slack channel with service names
- **Project Grouping**: Organizes issues by application/project name
- **Rich Formatting**: Color-coded Slack messages with issue counts and affected services

## Prerequisites

### 1. Snyk API Token

Get your Snyk API token:

**Personal Token** (Individual use):
1. Log in to [Snyk](https://app.snyk.io)
2. Go to Account Settings → General → API Token
3. Click "Click to show" and copy your token

**Service Account Token** (Recommended for CI/CD):
1. In Snyk, go to Settings → Service Accounts (Group or Org level)
2. Click "Create a service account"
3. Set name, description, and permissions
4. Copy the generated token

### 2. Snyk Organization ID

1. In Snyk, navigate to Settings → General
2. Copy your Organization ID

### 3. Slack Bot Setup

1. Go to [Slack API](https://api.slack.com/apps) → Create New App → From scratch
2. Name your app: "Snyk Security Bot"
3. Select your workspace
4. Go to **OAuth & Permissions** → **Scopes**
5. Add these Bot Token Scopes:
   - `chat:write` (Send messages)
   - `channels:read` (Access channel info)
6. Click **Install to Workspace**
7. Copy the **Bot User OAuth Token** (starts with `xoxb-`)
8. Invite bot to your channel: `/invite @Snyk Security Bot`

## Setup Instructions

### 1. Add GitHub Secrets

Go to your repository → Settings → Secrets and variables → Actions

Add these secrets:
- `SNYK_TOKEN`: Your Snyk API token
- `SNYK_ORG_ID`: Your Snyk organization ID
- `SLACK_BOT_TOKEN`: Your Slack bot token
- `SLACK_CHANNEL`: Channel name (e.g., `security-alerts`) or ID

## Repository Structure

Organize your files like this:

```
your-repo/
├── .github/
│   └── workflows/
│       └── daily-snyk-report.yml
├── scripts/
│   ├── security/
│   │   ├── snyk-report.py
│   │   ├── requirements.txt (optional)
│   │   └── README.md (optional)
│   └── other-scripts/
└── README.md
```

### 2. Create Workflow File

Create `.github/workflows/daily-snyk-report.yml`:

```yaml
name: Daily Snyk Security Report

on:
  schedule:
    # Run daily at 9:00 AM EST (2:00 PM UTC during EST, 1:00 PM UTC during EDT)
    - cron: '0 14 * * *'  # EST (Nov-Mar)
    # Note: Adjust to '0 13 * * *' during EDT (Mar-Nov) if needed
  workflow_dispatch: # Allow manual trigger

jobs:
  snyk-security-report:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install requests slack-sdk

      - name: Run Snyk Security Report
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
          SNYK_ORG_ID: ${{ secrets.SNYK_ORG_ID }}
          SLACK_BOT_TOKEN: ${{ secrets.SLACK_BOT_TOKEN }}
          SLACK_CHANNEL: ${{ secrets.SLACK_CHANNEL }}
          GITHUB_REPOSITORY: ${{ github.repository }}
        run: |
          python scripts/security/snyk-report.py
```

### 3. Create Python Script

Create `scripts/security/snyk-report.py`:

```python
#!/usr/bin/env python3

import os
import json
import requests
from datetime import datetime
from typing import List, Dict
from urllib.parse import urlparse, parse_qs
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

class SnykSecurityReporter:
    def __init__(self):
        self.snyk_token = os.environ.get('SNYK_TOKEN')
        self.org_id = os.environ.get('SNYK_ORG_ID')
        self.slack_bot_token = os.environ.get('SLACK_BOT_TOKEN')
        self.slack_channel = os.environ.get('SLACK_CHANNEL', 'security-alerts')
        self.github_repo = os.environ.get('GITHUB_REPOSITORY', '')
        
        self.api_url = 'https://api.snyk.io/rest'
        self.api_version = '2024-10-15'
        
        # Validate required environment variables
        if not all([self.snyk_token, self.org_id]):
            raise ValueError('SNYK_TOKEN and SNYK_ORG_ID are required')
        
        # Initialize Slack client
        self.slack_client = None
        if self.slack_bot_token:
            self.slack_client = WebClient(token=self.slack_bot_token)
            print("✅ Slack bot client initialized")
        else:
            print("⚠️  No Slack bot token provided, skipping notifications")

    def make_snyk_request(self, endpoint: str, params: Dict = None) -> Dict:
        """Make authenticated request to Snyk API"""
        url = f"{self.api_url}{endpoint}"
        headers = {
            'Authorization': f'token {self.snyk_token}',
            'Content-Type': 'application/vnd.api+json'
        }
        
        request_params = {'version': self.api_version}
        if params:
            request_params.update(params)
        
        try:
            response = requests.get(url, headers=headers, params=request_params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"❌ Snyk API request failed: {e}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"Response: {e.response.text}")
            raise

    def get_all_projects(self) -> List[Dict]:
        """Fetch all projects from Snyk organization"""
        print("📋 Fetching projects from Snyk...")
        all_projects = []
        cursor = None
        
        while True:
            params = {'limit': 100}
            if cursor:
                params['starting_after'] = cursor
                
            response = self.make_snyk_request(f'/orgs/{self.org_id}/projects', params)
            projects = response.get('data', [])
            all_projects.extend(projects)
            
            # Handle pagination
            next_link = response.get('links', {}).get('next')
            if not next_link:
                break
                
            # Extract cursor from next link
            parsed_url = urlparse(next_link)
            query_params = parse_qs(parsed_url.query)
            cursor = query_params.get('starting_after', [None])[0]
            
        print(f"📋 Found {len(all_projects)} projects")
        return all_projects

    def get_security_issues(self) -> List[Dict]:
        """Fetch critical, high, and medium severity issues"""
        print("🔍 Fetching security issues from Snyk...")
        all_issues = []
        cursor = None
        
        while True:
            params = {
                'limit': 100,
                'effective_severity_level': 'critical,high,medium'  # Get critical, high, medium
            }
            if cursor:
                params['starting_after'] = cursor
                
            response = self.make_snyk_request(f'/orgs/{self.org_id}/issues', params)
            issues = response.get('data', [])
            all_issues.extend(issues)
            
            # Handle pagination
            next_link = response.get('links', {}).get('next')
            if not next_link:
                break
                
            parsed_url = urlparse(next_link)
            query_params = parse_qs(parsed_url.query)
            cursor = query_params.get('starting_after', [None])[0]
            
        print(f"🔍 Found {len(all_issues)} critical/high/medium severity issues")
        return all_issues

    def process_security_data(self) -> Dict:
        """Process Snyk data and generate report"""
        print("📊 Processing security data...")
        
        try:
            projects = self.get_all_projects()
            issues = self.get_security_issues()
            
            # Create project ID to name mapping
            project_map = {}
            for project in projects:
                project_id = project['id']
                project_name = project.get('attributes', {}).get('name', 'Unknown Project')
                project_map[project_id] = project_name
            
            # Group issues by project
            project_issues = {}
            
            for issue in issues:
                # Get project info from scan_item relationship
                scan_item = issue.get('relationships', {}).get('scan_item', {}).get('data', {})
                if not scan_item:
                    continue
                    
                project_id = scan_item.get('id')
                project_name = project_map.get(project_id, f'Unknown Project ({project_id})')
                severity = issue.get('attributes', {}).get('effective_severity_level', 'unknown')
                
                # Initialize project entry
                if project_name not in project_issues:
                    project_issues[project_name] = {
                        'critical': 0,
                        'high': 0,
                        'medium': 0,
                        'total': 0
                    }
                
                # Count issues by severity
                if severity in ['critical', 'high', 'medium']:
                    project_issues[project_name][severity] += 1
                    project_issues[project_name]['total'] += 1
            
            # Calculate totals
            total_critical = sum(stats['critical'] for stats in project_issues.values())
            total_high = sum(stats['high'] for stats in project_issues.values())
            total_medium = sum(stats['medium'] for stats in project_issues.values())
            
            # Sort projects by severity (critical first, then high, then medium)
            sorted_projects = []
            for name, stats in project_issues.items():
                sorted_projects.append({
                    'name': name,
                    'critical': stats['critical'],
                    'high': stats['high'], 
                    'medium': stats['medium'],
                    'total': stats['total']
                })
            
            # Sort by total issues (critical weighted highest)
            sorted_projects.sort(
                key=lambda x: (x['critical'] * 10 + x['high'] * 5 + x['medium']), 
                reverse=True
            )
            
            report = {
                'generated_at': datetime.utcnow().isoformat() + 'Z',
                'organization_id': self.org_id,
                'summary': {
                    'total_projects': len(project_issues),
                    'projects_with_issues': len([p for p in sorted_projects if p['total'] > 0]),
                    'total_critical': total_critical,
                    'total_high': total_high,
                    'total_medium': total_medium,
                    'total_issues': total_critical + total_high + total_medium
                },
                'projects': [p for p in sorted_projects if p['total'] > 0]  # Only projects with issues
            }
            
            return report
            
        except Exception as e:
            print(f"❌ Error processing security data: {e}")
            raise

    def create_slack_message(self, report: Dict) -> Dict:
        """Create Slack message with security report"""
        summary = report['summary']
        
        # Determine overall status and color
        if summary['total_critical'] > 0:
            color = '#FF0000'  # Red
            status_emoji = '🚨'
            status_text = 'CRITICAL SECURITY ISSUES DETECTED'
        elif summary['total_high'] > 0:
            color = '#FF8C00'  # Orange
            status_emoji = '⚠️'
            status_text = 'HIGH SEVERITY ISSUES DETECTED'
        elif summary['total_medium'] > 0:
            color = '#FFD700'  # Yellow
            status_emoji = '⚡'
            status_text = 'MEDIUM SEVERITY ISSUES DETECTED'
        else:
            color = '#36A64F'  # Green
            status_emoji = '🎉'
            status_text = 'NO SECURITY ISSUES DETECTED'
        
        # Build message blocks
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{status_emoji} Daily Snyk Security Report"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Status:* {status_text}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Report Time:* {datetime.now().strftime('%Y-%m-%d %I:%M %p EST')}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Projects Scanned:* {summary['total_projects']}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Projects with Issues:* {summary['projects_with_issues']}"
                    }
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Issue Summary:*\n🔴 Critical: *{summary['total_critical']}*\n🟠 High: *{summary['total_high']}*\n🟡 Medium: *{summary['total_medium']}*\n📊 Total: *{summary['total_issues']}*"
                }
            }
        ]
        
        # Add critical and high severity services breakdown
        critical_projects = [p for p in report['projects'] if p['critical'] > 0]
        high_projects = [p for p in report['projects'] if p['high'] > 0 and p['critical'] == 0]
        
        if critical_projects or high_projects:
            severity_breakdown = ""
            
            # Critical services
            if critical_projects:
                critical_names = [p['name'] for p in critical_projects]
                if len(critical_names) <= 3:
                    critical_text = ", ".join(critical_names)
                else:
                    critical_text = f"{', '.join(critical_names[:3])} ... <https://app.snyk.io/org/{self.org_id}|click here for more>"
                
                severity_breakdown += f"🔴 *Critical Issues in:*\n{critical_text}\n\n"
            
            # High severity services  
            if high_projects:
                high_names = [p['name'] for p in high_projects]
                if len(high_names) <= 3:
                    high_text = ", ".join(high_names)
                else:
                    high_text = f"{', '.join(high_names[:3])} ... <https://app.snyk.io/org/{self.org_id}|click here for more>"
                
                severity_breakdown += f"🟠 *High Issues in:*\n{high_text}"
            
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": severity_breakdown.strip()
                }
            })
        
        # Add detailed projects breakdown (top 10)
        if report['projects']:
            project_text = ""
            for i, project in enumerate(report['projects'][:10], 1):
                indicators = []
                if project['critical'] > 0:
                    indicators.append('🔴')
                if project['high'] > 0:
                    indicators.append('🟠')
                if project['medium'] > 0:
                    indicators.append('🟡')
                
                indicator_str = ''.join(indicators)
                project_text += f"{i}. {indicator_str} *{project['name']}*\n"
                project_text += f"   Critical: {project['critical']}, High: {project['high']}, Medium: {project['medium']}\n"
            
            if len(report['projects']) > 10:
                project_text += f"\n_... and {len(report['projects']) - 10} more projects with issues_"
            
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Detailed Project Breakdown:*\n{project_text}"
                }
            })
        
        # Add action buttons
        action_elements = [
            {
                "type": "button",
                "text": {
                    "type": "plain_text",
                    "text": "View in Snyk"
                },
                "url": f"https://app.snyk.io/org/{self.org_id}",
                "style": "primary"
            }
        ]
        
        if self.github_repo:
            action_elements.append({
                "type": "button",
                "text": {
                    "type": "plain_text",
                    "text": "View GitHub Action"
                },
                "url": f"https://github.com/{self.github_repo}/actions"
            })
        
        blocks.append({
            "type": "actions",
            "elements": action_elements
        })
        
        return {
            "channel": self.slack_channel,
            "username": "Snyk Security Bot",
            "icon_emoji": ":shield:",
            "attachments": [{
                "color": color,
                "blocks": blocks
            }]
        }

    def send_slack_notification(self, report: Dict) -> bool:
        """Send report to Slack"""
        if not self.slack_client:
            print("⚠️  No Slack client available, skipping notification")
            return False
        
        try:
            message = self.create_slack_message(report)
            response = self.slack_client.chat_postMessage(**message)
            
            if response["ok"]:
                print(f"✅ Slack notification sent to #{self.slack_channel}")
                return True
            else:
                print(f"❌ Slack API error: {response.get('error', 'Unknown error')}")
                return False
                
        except SlackApiError as e:
            print(f"❌ Slack API error: {e.response['error']}")
            return False
        except Exception as e:
            print(f"❌ Unexpected error sending Slack notification: {e}")
            return False

    def print_summary(self, report: Dict):
        """Print summary to console"""
        summary = report['summary']
        
        print("\n" + "="*70)
        print("📊 DAILY SNYK SECURITY REPORT SUMMARY")
        print("="*70)
        print(f"📅 Generated: {datetime.now().strftime('%Y-%m-%d %I:%M %p EST')}")
        print(f"🏢 Organization: {self.org_id}")
        print(f"📋 Projects Scanned: {summary['total_projects']}")
        print(f"⚠️  Projects with Issues: {summary['projects_with_issues']}")
        print(f"🔴 Critical Issues: {summary['total_critical']}")
        print(f"🟠 High Issues: {summary['total_high']}")
        print(f"🟡 Medium Issues: {summary['total_medium']}")
        print(f"📊 Total Issues: {summary['total_issues']}")
        
        if report['projects']:
            print(f"\n🔴 CRITICAL ISSUES:")
            critical_projects = [p for p in report['projects'] if p['critical'] > 0]
            if critical_projects:
                critical_names = [p['name'] for p in critical_projects]
                if len(critical_names) <= 3:
                    print(f"   Services: {', '.join(critical_names)}")
                else:
                    print(f"   Services: {', '.join(critical_names[:3])} ... and {len(critical_names) - 3} more")
            else:
                print("   No critical issues found")
            
            print(f"\n🟠 HIGH ISSUES:")
            high_projects = [p for p in report['projects'] if p['high'] > 0]
            if high_projects:
                high_names = [p['name'] for p in high_projects]
                if len(high_names) <= 3:
                    print(f"   Services: {', '.join(high_names)}")
                else:
                    print(f"   Services: {', '.join(high_names[:3])} ... and {len(high_names) - 3} more")
            else:
                print("   No high issues found")
                
            print(f"\n🎯 TOP 5 PROJECTS WITH ISSUES:")
            for i, project in enumerate(report['projects'][:5], 1):
                indicators = []
                if project['critical'] > 0: indicators.append('🔴')
                if project['high'] > 0: indicators.append('🟠') 
                if project['medium'] > 0: indicators.append('🟡')
                
                print(f"{i}. {''.join(indicators)} {project['name']}")
                print(f"   Critical: {project['critical']}, High: {project['high']}, Medium: {project['medium']}")
        else:
            print(f"\n🎉 All projects are secure!")
        
        print("="*70)

    def run(self):
        """Main execution method"""
        print("🚀 Starting Daily Snyk Security Report...")
        print(f"⏰ Report Time: {datetime.now().strftime('%Y-%m-%d %I:%M %p EST')}")
        
        try:
            # Generate security report
            report = self.process_security_data()
            
            # Send Slack notification
            slack_sent = self.send_slack_notification(report)
            
            # Print console summary
            self.print_summary(report)
            
            if slack_sent:
                print("\n✅ Daily security report sent to Slack successfully!")
            else:
                print("\n⚠️ Daily security report completed, but Slack notification failed!")
            
        except Exception as e:
            print(f"\n❌ Report generation failed: {e}")
            exit(1)

if __name__ == "__main__":
    reporter = SnykSecurityReporter()
    reporter.run()
```

### 4. Optional: Add Requirements File

Create `scripts/security/requirements.txt` for better dependency management:

```txt
requests>=2.31.0
slack-sdk>=3.19.0
```

Then update your workflow to use it:

```yaml
      - name: Install dependencies
        run: |
          pip install -r scripts/security/requirements.txt
```

### 5. Optional: Add Documentation

Create `scripts/security/README.md` to document your security scripts:

```markdown
# Security Scripts

## Daily Snyk Report
- **File**: `snyk-report.py`
- **Purpose**: Daily security vulnerability reporting
- **Schedule**: 9:00 AM EST daily
- **Output**: Slack notifications

## Future Scripts
- Add other security automation scripts here
```

## Alternative Directory Structures

You can organize it however makes sense for your team:

### Option 1: By Tool
```
scripts/
├── snyk/
│   ├── daily-report.py
│   └── vulnerability-scanner.py
├── sonarqube/
│   └── code-quality-report.py
└── dependabot/
    └── dependency-report.py
```

### Option 2: By Function  
```
scripts/
├── reporting/
│   ├── security-report.py
│   └── performance-report.py
├── monitoring/
│   └── health-check.py
└── deployment/
    └── deploy-helper.py
```

### Option 3: Flat Structure
```
scripts/
├── snyk-daily-report.py
├── security-scan.py
├── performance-monitor.py
└── requirements.txt
```

## Configuration

### Environment Variables

| Variable | Description | Required | Example |
|----------|-------------|----------|---------|
| `SNYK_TOKEN` | Your Snyk API token | Yes | `abc123...` |
| `SNYK_ORG_ID` | Your Snyk organization ID | Yes | `4a18d42f-0706-4ad0-b127-24078731fbed` |
| `SLACK_BOT_TOKEN` | Slack bot token | Yes | `xoxb-123...` |
| `SLACK_CHANNEL` | Slack channel name or ID | Yes | `security-alerts` |
| `GITHUB_REPOSITORY` | GitHub repo (auto-populated) | Auto | `owner/repo-name` |

### Timezone Configuration

The workflow is set to run at 9:00 AM EST:
- **EST (Nov-Mar)**: `cron: '0 14 * * *'` (2:00 PM UTC)  
- **EDT (Mar-Nov)**: `cron: '0 13 * * *'` (1:00 PM UTC)

Update the cron schedule in the workflow file if needed.

### Slack Channel Configuration

You can specify the Slack channel in several ways:

1. **Channel Name**: Use the channel name (e.g., `security-alerts`)
2. **Channel ID**: Use the channel ID (e.g., `C1234567890`) - more reliable
3. **Private Channels**: Bot must be invited to private channels first
4. **Direct Messages**: Use a user ID to send DMs (e.g., `U1234567890`)

To find a channel ID:
- Right-click on the channel in Slack → **Copy Link**
- The ID is the last part: `https://yourworkspace.slack.com/archives/C1234567890`

## Sample Slack Message Output

The Slack message will include:

### Header Section
```
🚨 Daily Snyk Security Report
Status: CRITICAL SECURITY ISSUES DETECTED
Report Time: 2025-09-02 09:00 AM EST
Projects Scanned: 25
Projects with Issues: 8
```

### Issue Summary
```
🔴 Critical: 3
🟠 High: 12  
🟡 Medium: 24
📊 Total: 39
```

### Service Names for Critical & High
```
🔴 Critical Issues in:
user-service, payment-api, auth-service ... click here for more

🟠 High Issues in:  
web-frontend, mobile-app, data-processor ... click here for more
```

### Detailed Breakdown
```
1. 🔴🟠 user-service
   Critical: 2, High: 4, Medium: 1

2. 🔴🟠 payment-api  
   Critical: 1, High: 3, Medium: 2
```

## Manual Testing

Test the workflow manually:

1. Go to **Actions** tab in your GitHub repository
2. Find "Daily Snyk Security Report" workflow
3. Click **Run workflow** → **Run workflow**

## Troubleshooting

### Common Issues

1. **API Authentication Failed**
   - Verify `SNYK_TOKEN` is correct and has API access
   - Check `SNYK_ORG_ID` matches your organization

2. **Slack Message Failed**
   - Ensure bot is invited to the channel: `/invite @Snyk Security Bot`
   - Verify `SLACK_BOT_TOKEN` starts with `xoxb-`
   - Check bot has `chat:write` permission

3. **Script Path Issues**
   - Verify the script is in `scripts/security/snyk-report.py`
   - Check the workflow uses the correct path
   - Ensure the file is executable (shouldn't matter in CI, but good practice)

4. **No Issues Found**
   - This is normal if no critical/high/medium issues exist
   - Verify projects have been scanned in Snyk recently

5. **Timezone Issues**
   - GitHub Actions runs on UTC
   - Adjust cron schedule for EST/EDT as needed

### Testing Slack Integration

Test your Slack bot setup with a simple Python script:

```python
from slack_sdk import WebClient

client = WebClient(token="your-bot-token")
response = client.chat_postMessage(
    channel="your-channel",
    text="Test message from Snyk bot!"
)
print(f"Message sent: {response['ok']}")
```

## API Reference

This action uses the Snyk REST API with the following endpoints:

- `GET /rest/orgs/{org_id}/projects` - List all projects
- `GET /rest/orgs/{org_id}/issues` - Get issues with severity filtering

For complete API documentation, visit: https://docs.snyk.io/snyk-api/reference

## Security Considerations

- **Token Storage**: Always store tokens as GitHub secrets
- **Token Permissions**: Use the principle of least privilege
- **Service Accounts**: Prefer service accounts over personal tokens for automation
- **Token Rotation**: Regularly rotate your API tokens

## Support

For issues related to:
- **Snyk API**: Contact [Snyk Support](https://support.snyk.io)
- **GitHub Actions**: Check the [GitHub Actions documentation](https://docs.github.com/en/actions)
- **Slack API**: Visit [Slack API documentation](https://api.slack.com/)

---

**Note**: This action requires a Snyk account with API access. Free and Team plans have limited API functionality compared to Enterprise plans.
