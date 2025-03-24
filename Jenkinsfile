#!groovy
pipeline {
  environment {
    PROJECT_NAME = "keyple-card-calypso-java-lib"
    PROJECT_BOT_NAME = "Eclipse Keyple Bot"
  }
  agent { kubernetes { yaml javaBuilder('2.0') } }
  stages {
    stage('Import keyring') {
      when { expression { env.GIT_URL.startsWith('https://github.com/eclipse-keyple/keyple-') && env.CHANGE_ID == null } }
      steps { container('java-builder') {
        withCredentials([file(credentialsId: 'secret-subkeys.asc', variable: 'KEYRING')]) { sh 'import_gpg "${KEYRING}"' }
      } }
    }
    stage('Prepare settings') { steps { container('java-builder') {
      script {
        env.KEYPLE_VERSION = sh(script: 'grep version gradle.properties | cut -d= -f2 | tr -d "[:space:]"', returnStdout: true).trim()
        env.GIT_COMMIT_MESSAGE = sh(script: 'git log --format=%B -1 | head -1 | tr -d "\n"', returnStdout: true)
        env.SONAR_USER_HOME = '/home/jenkins'
        echo "Building version ${env.KEYPLE_VERSION} in branch ${env.GIT_BRANCH}"
        deployRelease = env.GIT_URL == "https://github.com/eclipse-keyple/${env.PROJECT_NAME}.git" && (env.GIT_BRANCH == "main" || env.GIT_BRANCH.startsWith("hotfixes-")) && env.CHANGE_ID == null && env.GIT_COMMIT_MESSAGE.startsWith("Release ${env.KEYPLE_VERSION}")
        deploySnapshot = !deployRelease && env.GIT_URL == "https://github.com/eclipse-keyple/${env.PROJECT_NAME}.git" && (env.GIT_BRANCH == "main" || env.GIT_BRANCH.startsWith("hotfixes-")) && env.CHANGE_ID == null
      }
      sh "chmod +x ./gradlew ./scripts/*.sh"
    } } }
    stage('Check version') {
      steps { container('java-builder') {
        sh "./scripts/check_version.sh ${env.KEYPLE_VERSION}"
      } }
    }
    stage('Build and Test') {
      when { expression { !deploySnapshot && !deployRelease } }
      steps { container('java-builder') {
        sh './gradlew clean build test --no-build-cache --info --stacktrace'
        junit testResults: 'build/test-results/test/*.xml', allowEmptyResults: true
      } }
    }
    stage('Build and Publish Snapshot') {
      when { expression { deploySnapshot } }
      steps { container('java-builder') {
        configFileProvider([configFile(fileId: 'gradle.properties', targetLocation: '/home/jenkins/agent/gradle.properties')]) {
          sh './gradlew clean build test publish --info --stacktrace'
        }
        junit testResults: 'build/test-results/test/*.xml', allowEmptyResults: true
      } }
    }
    stage('Build and Publish Release') {
      when { expression { deployRelease } }
      steps { container('java-builder') {
        configFileProvider([configFile(fileId: 'gradle.properties', targetLocation: '/home/jenkins/agent/gradle.properties')]) {
          sh './gradlew clean build test release --info --stacktrace'
        }
        junit testResults: 'build/test-results/test/*.xml', allowEmptyResults: true
      } }
    }
    stage('Update GitHub Pages') {
      when { expression { deploySnapshot || deployRelease } }
      steps { container('java-builder') {
        sh "./scripts/prepare_javadoc.sh ${env.PROJECT_NAME} ${env.KEYPLE_VERSION} ${deploySnapshot}"
        dir("${env.PROJECT_NAME}") {
          withCredentials([usernamePassword(credentialsId: 'github-bot', passwordVariable: 'GIT_PASSWORD', usernameVariable: 'GIT_USERNAME')]) {
            sh '''
            git add -A
            git config user.email "${PROJECT_NAME}-bot@eclipse.org"
            git config user.name "${PROJECT_BOT_NAME}"
            git commit --allow-empty -m "docs: update documentation ${JOB_NAME}-${BUILD_NUMBER}"
            git log --graph --abbrev-commit --date=relative -n 5
            git push "https://${GIT_USERNAME}:${GIT_PASSWORD}@github.com/eclipse-keyple/${PROJECT_NAME}.git" HEAD:doc
            '''
          }
        }
      } }
    }
    stage('Publish Code Quality') {
      when { expression { env.GIT_URL.startsWith('https://github.com/eclipse-keyple/keyple-') } }
      steps { container('java-builder') {
        catchError(buildResult: 'SUCCESS', message: 'Unable to log code quality to Sonar.', stageResult: 'FAILURE') {
          withCredentials([string(credentialsId: 'sonarcloud-token', variable: 'SONAR_LOGIN')]) {
            sh './gradlew sonarqube --info --stacktrace'
          }
        }
      } }
    }
    stage('Publish packaging to Eclipse') {
      when { expression { deploySnapshot || deployRelease } }
      steps { container('java-builder') { sshagent(['projects-storage.eclipse.org-bot-ssh']) { sh 'publish_packaging' } } }
    }
  }
  post { always { container('java-builder') {
    archiveArtifacts artifacts: 'build*/libs/**', allowEmptyArchive: true
    archiveArtifacts artifacts: 'build*/reports/tests/**', allowEmptyArchive: true
    archiveArtifacts artifacts: 'build*/reports/jacoco/test/html/**', allowEmptyArchive: true
  } } }
}
