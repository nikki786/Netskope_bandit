Web Application Security Lab
1. Create a public repository with vulnerable Python or Go language code for task #2
2. Develop a GitHub Action 
3. To perform a code scan with Bandit or gosec with every pull request opened 
4. If any Critical or above vulnerability identified -> Block the pull request with a comment ‘Block’ 
5. Else auto-merge the pull request with a comment ‘Successful’

6. Enable the GitHub Advanced Security -> Code Scanning for above repo for task #4

7. Write a python or go script to:

8. Fetch all code scanning alerts for above repo with severity High or above 
9. Obtain ‘Likelihood of exploitability’ from https://cwe.mitre.org for each vulnerability 
10. Print list of vulnerabilities with severity High or above AND ‘Likelihood of exploitability’ High or above 
