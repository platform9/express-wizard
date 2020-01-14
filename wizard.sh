#!/bin/bash

wizard_basedir=~/.pf9-wizard
wizard_venv=${wizard_basedir}/wizard-venv
venv_python="${wizard_venv}/bin/python"
venv_activate="${wizard_venv}/bin/activate"
#wizard_branch="master"
wizard_branch="tomchris/add-region-validate"
wizard_url="https://raw.githubusercontent.com/platform9/express-wizard/${wizard_branch}/wizard.py"
wizard_tmp_script=/tmp/pf9-wizard.py

# functions
usage() {
    echo "Usage: $(basename $0) [-i|--init]"
    exit 1
}

assert() {
    if [ $# -gt 0 ]; then echo "ASSERT: ${1}"; fi
    exit 1
}

init_venv_python2() {
    echo "Initializing Virtual Environment (Python 2)"
    which virtualenv > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "ERROR: missing python package: virtualenv (attempting to install via 'pip install virtualenv')"
        pip install virtualenv > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo "ERROR: failed to install python package (attempting to install via 'sudo pip install virtualenv')"
            sudo pip install virtualenv > /dev/null 2>&1
            if [ $? -ne 0 ]; then
                assert "Please install the 'virtualenv' module using 'pip install virtualenv'"
            fi
        fi
    fi

    cd ${wizard_basedir}
    virtualenv ${wizard_venv} > /dev/null 2>&1
    if [ ! -r ${venv_python} ]; then assert "failed to initialize virtual environment"; fi
}

init_venv_python3() {
    echo "Initializing Virtual Environment (Python 3)"
    which virtualenv > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "ERROR: missing python package: virtualenv (attempting to install via 'pip3 install virtualenv')"
        pip3 install virtualenv > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo "ERROR: failed to install python package (attempting to install via 'sudo pip3 install virtualenv')"
            sudo pip3 install virtualenv > /dev/null 2>&1
            if [ $? -ne 0 ]; then
                assert "Please install the 'virtualenv' module using 'pip3 install virtualenv'"
            fi
        fi
    fi
    cd ${wizard_basedir}
    python3 -m venv ${wizard_venv} > /dev/null 2>&1
    if [ ! -r ${venv_python} ]; then assert "failed to initialize virtual environment"; fi
}

## main

# parse commandline
while [ $# -gt 0 ]; do
    case ${1} in
    -h|--help)
        usage
        ;;
    -i|--init)
        if [ -d ${wizard_basedir} ]; then
            rm -rf ${wizard_basedir}
            if [ -d ${wizard_basedir} ]; then assert "failed to remove ${wizard_basedir}"; fi
        fi
        ;;
    esac
    shift
done

# initialize installation directory
if [ ! -d ${wizard_basedir} ]; then
    mkdir -p ${wizard_basedir}
    if [ ! -d ${wizard_basedir} ]; then assert "failed to create directory: ${wizard_basedir}"; fi
fi

# validate python stack
which python > /dev/null 2>&1
if [ $? -ne 0 ]; then assert "Python stack missing"; fi

# configure python virtual environment
if [ "$(ls -A ${wizard_venv} > /dev/null 2>&1; echo $?)" -ne 0 ]; then
    {
        [ -x "$(which python3)" ] &&
        python_version="$(python3 <<< 'import sys; print(sys.version_info[0])')"
    } || {
        python_version="$(python <<< "import sys; print(sys.version_info[0])")"
    }
    case ${python_version} in
    2)
        init_venv_python2
        ;;
    3)
        init_venv_python3
        ;;
    *)
        assert "unsupported python version"
    esac
else
    echo "INFO: using exising virtual environment"
fi

# remove cached version of pf9-wizard.py
if [ -f ${wizard_tmp_script} ]; then
    rm -f ${wizard_tmp_script}
    if [ -f ${wizard_tmp_script} ]; then assert "failed to remove cached file"; fi
fi

# download pf9-wizard
if [ "$(curl -s --fail -o ${wizard_tmp_script} ${wizard_url}; echo $?)" -ne 0 ]; then
    assert "failed to download Platform9 Express Wizard (from ${wizard_url})"; fi

# upgrade pip
(. ${venv_activate} && pip install pip --upgrade > /dev/null 2>&1)

# install Openstack CLI
reqs=https://raw.githubusercontent.com/platform9/support-locker/master/openstack-clients/requirements.txt
constraints=http://raw.githubusercontent.com/openstack/requirements/stable/pike/upper-constraints.txt
(. ${venv_activate} && pip install --upgrade --requirement ${reqs} --constraint ${constraints} > /dev/null 2>&1)


# start pf9-wizard in virtual environment
flag_started=0
while [ ${flag_started} -eq 0 ]; do
    (. ${venv_activate} && ${venv_python} ${wizard_tmp_script})
    if [ $? -eq 0 ]; then
        flag_started=1
    else
        stdout=$(. ${venv_activate} && ${venv_python} ${wizard_tmp_script})
        echo "${stdout}" | grep "ASSERT: Failed to import python module:" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            module_name=$(echo "${stdout}" | cut -d : -f3 | awk -F ' ' '{print $1}' | sed -e "s/'//g")
            echo "--> attempting to installing missing module: [${module_name}]"
            if [ "${python_version}" == "2" ]; then
                (. ${venv_activate}; pip install ${module_name} > /dev/null 2>&1)
            elif [ "${python_version}" == "3" ]; then
                (. ${venv_activate}; python -m pip install ${module_name} > /dev/null 2>&1)
            fi
            if [ $? -ne 0 ]; then assert "failed to install missing module"; fi
        else
            assert "${stdout}"
        fi
    fi
done
