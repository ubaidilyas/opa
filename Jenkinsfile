pipeline {
  agent any
  stages {

    stage('Checkout') {
      steps {
        script {
          git branch: 'main', url: 'https://github.com/ubaidilyas/opa.git'
        }
      }
    }
    // Part of the job containing:
    // terraform init
    // terraform workspace
    // terraform plan
    // terraform show
    stage('Querry') {
      steps {
        script {
          sh "docker run -v ${env.WORKSPACE}:/azure openpolicyagent/opa:0.37.1  eval -d /azure/azure data.azure.secure -i /azure/not_ok.json | tee opa_result.txt > /dev/null"
        }
      }
    }

    stage('Approval') {
      when {
        not {
          equals expected: true, actual: params.autoApprove
        }
      }

      steps {
        script {
          def plan = readFile "${env.WORKSPACE}/opa_result.txt"
          input message: "Do you want to apply the plan with following OPA response?",
            parameters: [text(name: 'OPA Response', description: 'Please review the decision', defaultValue: plan)]
        }
      }
    }
    // Part of the job containing:
    // terraform apply
  }
}
