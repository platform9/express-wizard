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
}

init_venv_python3() {
    echo "Initializing Virtual Environment (Python 3)"
    cd ${wizard_basedir}
    python -m venv ${wizard_venv}
    if [ ! -r ${venv_python} ]; then assert "failed to initialize virtual environment"; fi
}

# validate python stack
which python > /dev/null 2>&1
if [ $? -ne 0 ]; then assert "Python stack missing"; fi

# initialize installation directory
if [ -d ${wizard_basedir} ]; then
    mkdir -p ${wizard_basedir}
    if [ ! -d ${wizard_basedir} ]; then assert "failed to create directory: ${wizard_basedir}"; fi
fi

# remove existing environment
if [ -f ${wizard_venv} ]; then
    rm -rf ${wizard_venv}
    if [ ! -f ${wizard_venv} ]; then assert "failed to remove virtual environment"; fi
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

# remove cached version of pf9-wizard.py
if [ -f ${wizard_tmp_script} ]; then
    rm -f ${wizard_tmp_script}
    if [ -f ${wizard_tmp_script} ]; then assert "failed to remove cached file"; fi
fi

# download pf9-wizard
curl -s -o ${wizard_tmp_script} ${wizard_url}
if [ ! -r ${wizard_tmp_script} ]; then assert "failed to download Platform9 Express Wizard (from ${wizard_url})"; fi

# activate python virtual environment
source ${venv_activate}

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
            echo "attempting in installing missing module: [${module_name}]"
            if [ "${python_version}" == "2" ]; then
                pip install ${module_name} > /dev/null 2>&1
            elif [ "${python_version}" == "3" ]; then
                source ${venv_activate}; python -m pip install ${module_name}
            fi
            if [ $? -ne 0 ]; then assert "failed to install missing module"; fi
        else
            assert "${stdout}"
        fi
    fi
done
