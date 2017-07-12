#!groovy

@Library('SovrinHelpers') _

def name = 'anoncreds'

def testUbuntu = {
    try {
        echo 'Ubuntu Test: Checkout csm'
        checkout scm

        helpers.shell('cp setup-charm.sh ci/setup-charm.sh')
        helpers.shell('sed -ir s/sudo// ci/setup-charm.sh')

        echo 'Ubuntu Test: Build docker image'
        def testEnv = dockerHelpers.build(name)

        testEnv.inside {
            echo 'Ubuntu Test: Install dependencies'
            testHelpers.installDeps(['pytest-asyncio'])

            echo 'Ubuntu Test: Test'
            testHelpers.testJunit()
        }
    }
    finally {
        echo 'Ubuntu Test: Cleanup'
        step([$class: 'WsCleanup'])
    }
}

def testWindows = {
    echo 'TODO: Implement me'
}

def testWindowsNoDocker = {
    try {
        echo 'Windows No Docker Test: Checkout csm'
        checkout scm

        testHelpers.createVirtualEnvAndExecute({ python, pip ->
            echo 'Windows No Docker Test: Install dependencies'
            testHelpers.installDepsBat(python, pip, ['pytest-asyncio'])

            echo 'Windows No Docker Test: Test'
            testHelpers.testJunitBat(python, pip)
        })
    }
    finally {
        echo 'Windows No Docker Test: Cleanup'
        step([$class: 'WsCleanup'])
    }
}

testAndPublish(name, [ubuntu: [anoncreds: testUbuntu], windows: [anoncreds: testWindowsNoDocker], windowsNoDocker: [anoncreds: testWindowsNoDocker]])
