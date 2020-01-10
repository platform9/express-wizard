#!/bin/bash

wizard_basedir=~/.pf9-wizard
wizard_venv=${wizard_basedir}/wizard-venv
venv_python="${wizard_venv}/bin/python"
venv_activate="${wizard_venv}/bin/activate"
wizard_url=https://raw.githubusercontent.com/platform9/express-wizard/master/wizard.py
wizard_tmp_script=/tmp/pf9-wizard.py

assert() {
    if [ $# -gt 0 ]; then echo "ASSERT: ${1}"; fi
    exit 1
}

init_venv_python2() {
    echo "Initializing Virtual Environment (Python 2)"
    cd ${wizard_basedir}
    virtualenv ${wizard_venv} > /dev/null 2>&1
    if [ ! -r ${venv_python} ]; then assert "failed to initialize virtual environment"; fi
    eval source ${venv_activate}
}

init_venv_python3() {
    echo "Initializing Virtual Environment (Python 2)"
}

# validate python stack
which python > /dev/null 2>&1
if [ $? -ne 0 ]; then assert "Python stack missing"; fi

# initialize installation directory
if [ ! -d ${wizard_basedir} ]; then
    mkdir -p ${wizard_basedir}
    if [ $? -ne 0 ]; then assert "failed to create directory: ${wizard_basedir}"; fi
fi

# configure python virtual environment
python_version=$(python <<< "import sys; print(sys.version_info[0])")
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

# download pf9-wizard
curl -s -o ${wizard_tmp_script} ${wizard_url}
if [ ! -r ${wizard_tmp_script} ]; then assert "failed to download Platform9 Express Wizard (from ${wizard_url})"; fi

# start pf9-wizard in virtual environment
eval ${venv_python} ${wizard_tmp_script}

