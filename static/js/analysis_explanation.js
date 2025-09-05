

class AnalysisExplainer {
    constructor() {
        this.explanations = {

            'permissions': {
                'title': 'Permission Analysis',
                'description': 'Examines app permissions to identify potentially dangerous or excessive permissions that could be misused.',
                'risk_levels': {
                    'high': 'These permissions are considered dangerous and can access sensitive user data or device functionality.',
                    'medium': 'These permissions can access restricted data or resources, but with less privacy impact.',
                    'low': 'These permissions provide access to harmless app-level features with minimal risk.'
                },
                'details': 'The permission score is calculated based on the number and types of permissions requested, with extra weight given to dangerous permissions.'
            },
            'code_signatures': {
                'title': 'Code Signature Analysis',
                'description': 'Evaluates the app\'s cryptographic signatures to verify authenticity and integrity.',
                'risk_levels': {
                    'high': 'The app is either unsigned or contains an invalid signature, which means it could be tampered with.',
                    'medium': 'The app is signed but with a certificate that couldn\'t be verified against trusted authorities.',
                    'low': 'The app is properly signed with a valid certificate from a trusted authority.'
                },
                'details': 'Code signing helps ensure the app comes from a legitimate developer and hasn\'t been modified after signing.'
            },
            'obfuscation': {
                'title': 'Code Obfuscation Detection',
                'description': 'Detects techniques used to hide or disguise app code functionality.',
                'risk_levels': {
                    'high': 'Heavy obfuscation detected, making code analysis difficult and potentially hiding malicious functionality.',
                    'medium': 'Moderate obfuscation detected, which is common for intellectual property protection but can also hide suspicious behavior.',
                    'low': 'Minimal or no obfuscation detected, code is relatively transparent.'
                },
                'details': 'While obfuscation is often used legitimately to protect intellectual property, malware authors commonly use it to evade detection.'
            },

            'network_activity': {
                'title': 'Network Activity Analysis',
                'description': 'Monitors all network connections made by the application during runtime.',
                'risk_levels': {
                    'high': 'Suspicious connections to known malicious servers or unexpected data exfiltration detected.',
                    'medium': 'Unencrypted data transmission or connections to tracking servers detected.',
                    'low': 'All network activity appears normal and uses secure protocols.'
                },
                'details': 'Network analysis evaluates both the destinations of connections and the nature of data being transmitted.'
            },
            'file_system': {
                'title': 'File System Interactions',
                'description': 'Monitors how the app reads from and writes to the device file system.',
                'risk_levels': {
                    'high': 'App attempts to access or modify sensitive system files or other apps\' data.',
                    'medium': 'App stores sensitive data without proper encryption or in insecure locations.',
                    'low': 'App properly manages files within its own directory and uses secure storage for sensitive data.'
                },
                'details': 'File system analysis helps identify data leakage risks and potential privilege escalation attempts.'
            },
            'runtime_behavior': {
                'title': 'Runtime Behavior Analysis',
                'description': 'Observes the app\'s behavior during execution to detect suspicious activities.',
                'risk_levels': {
                    'high': 'App exhibits behavior consistent with malware, such as privilege escalation attempts or data theft.',
                    'medium': 'App shows some concerning behaviors that might indicate privacy issues or performance problems.',
                    'low': 'App behavior is consistent with its stated purpose and functionality.'
                },
                'details': 'Runtime analysis can detect malicious behaviors that might not be apparent from static code analysis.'
            },

            'malware_signatures': {
                'title': 'Malware Signature Detection',
                'description': 'Compares app code against known malware patterns and signatures.',
                'risk_levels': {
                    'high': 'App contains code matching known malware signatures.',
                    'medium': 'App contains code that partially matches malware patterns or is similar to known suspicious code.',
                    'low': 'No matches to known malware signatures detected.'
                },
                'details': 'Signature detection is effective for identifying known malware variants but may miss new or heavily modified threats.'
            },
            'behavior_heuristics': {
                'title': 'Behavioral Heuristics',
                'description': 'Uses AI and pattern recognition to identify suspicious behavior patterns, even if they don\'t match known signatures.',
                'risk_levels': {
                    'high': 'Multiple suspicious behavior patterns detected that strongly indicate malicious intent.',
                    'medium': 'Some behavior patterns detected that could indicate either malicious activity or poor programming practices.',
                    'low': 'No suspicious behavior patterns detected.'
                },
                'details': 'Heuristic analysis can detect new or modified malware by recognizing suspicious behavior patterns.'
            },

            'vulnerabilities': {
                'title': 'Vulnerability Assessment',
                'description': 'Identifies known security vulnerabilities in the app\'s code or dependencies.',
                'risk_levels': {
                    'high': 'Critical security vulnerabilities detected that could allow remote code execution or unauthorized access.',
                    'medium': 'Moderate security issues found that could lead to data exposure or denial of service.',
                    'low': 'Minor security concerns or no vulnerabilities detected.'
                },
                'details': 'Vulnerability assessment checks for known CVEs (Common Vulnerabilities and Exposures) and insecure coding practices.'
            },
            'insecure_communications': {
                'title': 'Communication Security',
                'description': 'Evaluates the security of network communications for proper encryption and certificate validation.',
                'risk_levels': {
                    'high': 'Unencrypted transmission of sensitive data or critical certificate validation issues detected.',
                    'medium': 'Weak encryption or minor certificate validation issues found.',
                    'low': 'All communications properly secured with strong encryption and valid certificates.'
                },
                'details': 'Insecure communications can expose user data to interception through man-in-the-middle attacks.'
            },

            'data_leakage': {
                'title': 'Data Leakage Detection',
                'description': 'Identifies potential leakage of sensitive or personal user data.',
                'risk_levels': {
                    'high': 'App transmits sensitive personal data to third parties without proper disclosure or security.',
                    'medium': 'App collects more data than necessary for its functionality or has unclear privacy practices.',
                    'low': 'App properly handles sensitive data with appropriate security measures and transparency.'
                },
                'details': 'Data leakage analysis focuses on what data is collected and where it\'s being sent.'
            },
            'tracking': {
                'title': 'Tracking & Analytics',
                'description': 'Evaluates the app\'s use of tracking technologies and analytics services.',
                'risk_levels': {
                    'high': 'Excessive tracking detected, including persistent identifiers and location tracking without proper disclosure.',
                    'medium': 'Moderate use of tracking and analytics that may raise some privacy concerns.',
                    'low': 'Minimal or transparent use of analytics with proper anonymization and disclosure.'
                },
                'details': 'While analytics are common in apps, excessive tracking can violate user privacy and may indicate adware.'
            }
        };
    }

    
    getExplanation(category) {
        return this.explanations[category] || {
            title: 'Analysis Results',
            description: 'Detailed information about the analysis findings.',
            risk_levels: {
                high: 'High risk - immediate attention recommended',
                medium: 'Medium risk - review recommended',
                low: 'Low risk - generally safe'
            },
            details: 'Analysis evaluates various aspects of the application to identify potential security issues.'
        };
    }

    
    generateExplanationHTML(category, riskLevel = null) {
        const explanation = this.getExplanation(category);
        
        let html = `
            <div class="explanation-panel">
                <div class="explanation-header">
                    <h4>${explanation.title}</h4>
                    <button class="explanation-toggle" aria-label="Toggle explanation">
                        <i class="fas fa-chevron-down"></i>
                    </button>
                </div>
                <div class="explanation-content">
                    <p>${explanation.description}</p>`;
        
        if (riskLevel && explanation.risk_levels[riskLevel]) {
            html += `
                    <div class="risk-level ${riskLevel}">
                        <strong>Risk Level: ${riskLevel.charAt(0).toUpperCase() + riskLevel.slice(1)}</strong>
                        <p>${explanation.risk_levels[riskLevel]}</p>
                    </div>`;
        }
        
        html += `
                    <div class="explanation-details">
                        <p><strong>How this is analyzed:</strong> ${explanation.details}</p>
                    </div>
                </div>
            </div>`;
        
        return html;
    }

    
    attachExplanations(selector = '.analysis-result') {
        const resultElements = document.querySelectorAll(selector);
        
        resultElements.forEach(element => {
            const category = element.dataset.category;
            const riskLevel = element.dataset.risk;
            
            if (!category) return;
            
            const explanationHTML = this.generateExplanationHTML(category, riskLevel);
            element.insertAdjacentHTML('beforeend', explanationHTML);

            const toggleBtn = element.querySelector('.explanation-toggle');
            const content = element.querySelector('.explanation-content');
            
            if (toggleBtn && content) {
                toggleBtn.addEventListener('click', () => {
                    content.classList.toggle('expanded');
                    toggleBtn.querySelector('i').classList.toggle('fa-chevron-down');
                    toggleBtn.querySelector('i').classList.toggle('fa-chevron-up');
                });
            }
        });
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.analysisExplainer = new AnalysisExplainer();

    if (document.querySelector('.analysis-result, .result-section')) {
        window.analysisExplainer.attachExplanations();
    }
});
