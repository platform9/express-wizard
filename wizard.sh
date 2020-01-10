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
    #virtualenv ${wizard_venv} > /dev/null 2>&1
    virtualenv ${wizard_venv}
    if [ ! -r ${venv_python} ]; then assert "failed to initialize virtual environment"; fi
}

init_venv_python3() {
    echo "Initializing Virtual Environment (Python 2)"
}

# validate python stack
which python > /dev/null 2>&1
if [ $? -ne 0 ]; then assert "Python stack missing"; fi
echo "current python stack: $(which python)"

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

# remove cached version of pf9-wizard
if [ -f ${wizard_tmp_script} ]; then
    echo "removing cached copy: ${wizard_tmp_script}"
    rm -f ${wizard_tmp_script}
    if [ -f ${wizard_tmp_script} ]; then assert "failed to remove cached file"; fi
fi

# download pf9-wizard
echo "downloading: ${wizard_url}"
curl -s -o ${wizard_tmp_script} ${wizard_url}
if [ ! -r ${wizard_tmp_script} ]; then assert "failed to download Platform9 Express Wizard (from ${wizard_url})"; fi

# activate python virtual environment
echo "sourcing venv"
source ${venv_activate}
echo "new python stack: $(which python)"

# start pf9-wizard in virtual environment
flag_started=0
while [ ${flag_started} -eq 0 ]; do
    echo "starting: (. ${venv_activate} && ${venv_python} ${wizard_tmp_script}"
    (. ${venv_activate} && ${venv_python} ${wizard_tmp_script})
    ex=$?
    echo "exit status = ${ex}"
    if [ ${ex} -eq 0 ]; then
        flag_started=1
    else
        stdout=$(. ${venv_activate} && ${venv_python} ${wizard_tmp_script})
        echo "${stdout}" | grep "ASSERT: Failed to import python module:" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            module_name=$(echo "${stdout}" | cut -d : -f3)
            echo "attempting in installing missing module: ${module_name}"
            pip install ${module_name} > /dev/null 2>&1
            if [ $? -ne 0 ]; then assert "failed to install missing module"; fi
        else
            assert "${stdout}"
        fi
    fi
done
