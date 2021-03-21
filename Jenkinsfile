#!groovy
pipeline {
  environment {
    PROJECT_NAME = "keyple-java-card-calypso"
    PROJECT_BOT_NAME = "Eclipse Keyple Bot"
  }
  agent { kubernetes { yaml javaBuilder('2.0') } }
  stages {
    stage('Import keyring') {
      when { expression { env.GIT_URL.startsWith('https://github.com/eclipse/keyple-') && env.CHANGE_ID == null } }
      steps { container('java-builder') {
        withCredentials([file(credentialsId: 'secret-subkeys.asc', variable: 'KEYRING')]) { sh 'import_gpg "${KEYRING}"' }
      } }
    }
    stage('Prepare settings') { steps { container('java-builder') {
      script {
        env.KEYPLE_VERSION = sh(script: 'grep version gradle.properties | cut -d= -f2 | tr -d "[:space:]"', returnStdout: true).trim()
        env.GIT_COMMIT_MESSAGE = sh(script: 'git log --format=%B -1 | head -1 | tr -d "\n"', returnStdout: true)
        echo "Building version ${env.KEYPLE_VERSION} in branch ${env.GIT_BRANCH}"
        deployRelease = env.GIT_URL == "https://github.com/eclipse/${env.PROJECT_NAME}.git" && (env.GIT_BRANCH == "main" || env.GIT_BRANCH == "release-${env.KEYPLE_VERSION}") && env.CHANGE_ID == null && env.GIT_COMMIT_MESSAGE.startsWith("Release ${env.KEYPLE_VERSION}")
        deploySnapshot = !deployRelease && env.GIT_URL == "https://github.com/eclipse/${env.PROJECT_NAME}.git" && (env.GIT_BRANCH == "main" || env.GIT_BRANCH == "release-${env.KEYPLE_VERSION}") && env.CHANGE_ID == null
      }
    } } }
    stage('Build and Test:') {
      when { expression { !deploySnapshot && !deployRelease } }
      parallel {
        stage('Java 6') { steps { container('java-builder') {
          sh './gradlew clean build -P javaSourceLevel=1.6 -P javaTargetLevel=1.6 -P buildDir=build-6 --no-build-cache --info'
          junit testResults: 'build-6/test-results/test/*.xml', allowEmptyResults: true
        } } }
        stage('Java 8') { steps { container('java-builder') {
          sh './gradlew clean build -P javaSourceLevel=1.8 -P javaTargetLevel=1.8 -P buildDir=build-8 --no-build-cache --info'
          junit testResults: 'build-8/test-results/test/*.xml', allowEmptyResults: true
        } } }
        stage('Java 11') { steps { container('java-builder') {
          sh './gradlew clean build -P javaSourceLevel=11 -P javaTargetLevel=11 -P buildDir=build-11 --no-build-cache --info'
          junit testResults: 'build-11/test-results/test/*.xml', allowEmptyResults: true
        } } }
      }
    }
    stage('Publish Snapshot') {
      when { expression { deploySnapshot } }
      steps { container('java-builder') {
        configFileProvider([configFile(fileId: 'gradle.properties', targetLocation: '/home/jenkins/agent/gradle.properties')]) {
          sh './gradlew clean build test publish --info'
        }
        junit testResults: 'build/test-results/test/*.xml', allowEmptyResults: true
      } }
    }
    stage('Publish Release') {
      when { expression { deployRelease } }
      steps { container('java-builder') {
        configFileProvider([configFile(fileId: 'gradle.properties', targetLocation: '/home/jenkins/agent/gradle.properties')]) {
          sh './gradlew clean release --info'
        }
        junit testResults: 'build/test-results/test/*.xml', allowEmptyResults: true
      } }
    }
    stage('Publish Code Quality') {
      when { expression { env.GIT_URL.startsWith('https://github.com/eclipse/keyple-') } }
      steps { container('java-builder') {
        catchError(buildResult: 'SUCCESS', message: 'Unable to log code quality to Sonar.', stageResult: 'FAILURE') {
          withCredentials([string(credentialsId: 'sonarcloud-token', variable: 'SONAR_LOGIN')]) {
            sh './gradlew sonarqube --info'
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
