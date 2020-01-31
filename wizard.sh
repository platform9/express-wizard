#!/bin/bash

####################################################################################################
#
# Example:
#    Deploy and run wizard against master
#         ./wizard.sh 
#    Deploy and test wizard against master. Wizard will execute and then exit before the menu.
#         ./wizard.sh 
#    Use the current branch for the build and enable debugging
#         ./wizard.sh -d -b=$(git branch 2> /dev/null | sed -e '/^[^*]/d' -e 's/* \(.*\)/\1/')
#    Local deployment using the current branch debugging enabled (DEVELOPMENT ONLY!)
#         ./wizard.sh -l -d -b=$(git branch 2> /dev/null | sed -e '/^[^*]/d' -e 's/* \(.*\)/\1/')
#
####################################################################################################

set -o pipefail

start_time=$(date +"%s.%N")

assert() {
    if [ $# -gt 0 ]; then stdout_log "ASSERT: ${1}"; fi
    echo -e "\n\n"
    echo "$(tail ${log_file})"
    echo ""
    echo "Installation failed, Here are the last 10 lines from the log" 
    echo "The full installation log is available at ${log_file}"
    echo "If more information is needed re-run the install with --debug"
    exit 1
}

debugging() {
    if [[ ${debug_flag} ]]; then stdout_log "${1}"; fi
}

stdout_log(){
    if [[ ${debug_flag} ]]; then
	if (which bc > /dev/null 2>&1); then
	    output="DEBUGGING: $(date +"%T") : $(bc <<<$(date +"%s.%N")-${start_time}) :$(basename $0) : ${1}"
	else
	    output="DEBUGGING: $(date +"%T") : $(basename $0) : ${1}"
	fi            
        echo "${output}" 2>&1 | tee -a ${log_file}
    else
        echo "$1" 2>&1 | tee -a ${log_file}
    fi
}

parse_args() {
    for i in "$@"; do
      case $i in
	-h|--help)
	    echo "Usage: $(basename $0)"
	    echo "	  [-i|--init]"
	    echo "	  [-t|--test]"
	    echo "	  [-l|--local]"
	    echo "	  [-d|--debug=]"
	    echo "	  [-c|--config=]"
	    echo "	  [-b|--branch=]"
	    echo ""
	    exit 0
	    shift
	    ;;
	-b=*|--branch=*)
	    if [ -n ${i#*=} ]; then
		wizard_branch="${i#*=}"
	    else
		assert "Branch name must be provided";
	    fi
	    shift
	    ;;
	-c=*|--config=*)
	    config_file="${i#*=}"
	    if [ -z ${config_file} ];
		then assert "config file not provided: ${config_file}" 
	    elif [[ ! -r ${config_file} ]];
		then assert "failed to access config file: ${config_file}";
	    fi
	    shift
	    ;;
	-d|--debug)
	    debug_flag="${i#*=}"
	    shift
	    ;;
	-d=*|--debug=*)
	    debug_flag="${i#*=}"
	    shift
	    ;;
	-l|--local)
	    run_local="--local"
	    shift
	    ;;
	-t|--test)
	    test_wizard="--test"
	    shift
	    ;;
	-i|--init)
	    init_flag="--init"
	    shift
	    ;;
	*)
	echo "$i is not a valid command line option."
	echo ""
	echo "For help, please use $0 -h"
	echo ""
	exit 1
	;;
	esac
	shift
    done
}

init_venv_python() {
    if [[ ${python_version} == 2 ]]; then
        pyver="";
    else 
        pyver="3";
    fi
    stdout_log "Initializing Virtual Environment using Python ${python_version}"
    #Validate and initialize virtualenv
    if ! (virtualenv --version > /dev/null 2>&1); then
        debugging "Validating pip"
	if ! which pip > /dev/null 2>&1; then
            debugging "ERROR: missing package: pip (attempting to install using get-pip.py)"
            curl -s -o ${pip_path} ${pip_url}
            if [ ! -r ${pip_path} ]; then assert "failed to download get-pip.py (from ${pip_url})"; fi
            
            if [ ! python${pyver} ${pip_path} ]; then
                debugging "ERROR: failed to install package: pip (attempting to install via 'sudo get-pip.py')"
                if [ sudo python${pyver} ${pip_path} > /dev/null 2>&1 ]; then
                    assert "Please install package: pip"
                fi
            fi
        fi
	debugging "ERROR: missing python package: virtualenv (attempting to install via 'pip install virtualenv')"
        # Attemping to Install virtualenv
        if [ ! pip${pyver} install virtualenv > /dev/null 2>&1 ]; then
            debugging "ERROR: failed to install python package (attempting to install via 'sudo pip install virtualenv')"
            if ! sudo pip${pyver} install virtualenv > /dev/null 2>&1; then
                assert "Please install the 'virtualenv' module using 'pip install virtualenv'"
            fi
        fi
    fi
    if ! (virtualenv -p python${pyver} ${venv} > /dev/null 2>&1); then assert "Creation of virtual environment failed"; fi
    debugging "venv_python:"${venv_python}
    if [ ! -r ${venv_python} ]; then assert "failed to initialize virtual environment"; fi
    debugging "Upgrade pip"
    if ! (${venv_python} -m pip install pip --upgrade > /dev/null 2>&1); then assert "Pip upgrade failed"; fi
}

initialize_basedir() {
    debugging "Initializing: ${pf9_basedir}"
    if [[ -n "${init_flag}" ]]; then
	debugging "DELETEING pf9_basedir: ${pf9_basedir}"
	if [ -d "${pf9_basedir}" ]; then
	    rm -rf "${pf9_basedir}"
	    if [ -d "${pf9_basedir}" ]; then assert "failed to remove ${pf9_basedir}"; fi
	fi
    fi
    debugging "Ensuring ${pf9_basedir} Exist"
    if ! mkdir -p "${pf9_basedir}" > /dev/null 2>&1; then assert "failed to create directory: ${pf9_basedir}"; fi
    debugging "Ensuring $(dirname ${log_file}) Exist"
    if ! mkdir -p "$(dirname ${log_file})" > /dev/null 2>&1; then assert "failed to create log directory: $(dirname ${log_file})"; fi
    debugging "Ensuring ${log_file} Exist"
    if ! touch "${log_file}" > /dev/null 2>&1; then assert "failed to create log file: ${log_file}"; fi
    debugging "Ensuring $(dirname ${pf9_bin}) Exist"
    if ! mkdir -p "${pf9_bin}" > /dev/null 2>&1; then assert "failed to create bin directory: $(dirname ${pf9_bin})"; fi
    if [ ! -d "${pf9_basedir}" ]; then assert "failed to create directory: ${pf9_basedir}"; fi
}




## main

parse_args "$@"
cd ~
# Set global variables
if [ -z ${wizard_branch} ]; then wizard_branch=master; fi
# Set the path so double quotes don't use the litteral '~'
pf9_basedir=$(dirname ~/pf9/.) 
pip_path=${pf9_basedir}/get_pip.py
log_file=${pf9_basedir}/log/wizard_install.log
pf9_bin=${pf9_basedir}/bin
venv="${pf9_basedir}/pf9-venv"
venv_python="${venv}/bin/python"
venv_activate="${venv}/bin/activate"
wizard_url="git+git://github.com/platform9/express-wizard.git@${wizard_branch}#egg=express-wizard"
#https://raw.githubusercontent.com/platform9/express-wizard/${wizard_branch}/wizard.py"
pip_url="https://bootstrap.pypa.io/get-pip.py"
wizard_entrypoint=$(dirname ${venv_python})/wizard
cli_entrypoint=$(dirname ${venv_python})/express
wizard=${pf9_bin}/wizard
cli=${pf9_bin}/cli

# initialize installation directory
initialize_basedir

# configure python virtual environment
stdout_log "Configuring virtualenv"
if [ ! -f "${venv_activate}" ]; then
    debugging "Virtual Environment: ${venv} Doesn't not exist, Configuring."
    for ver in {3,2,''}; do #ensure python3 is first
	debugging "Checking Python${ver}: $(which python${ver})"
        if (which python${ver} > /dev/null 2>&1); then
	    python_version="$(python${ver} <<< 'import sys; print(sys.version_info[0])')"
	    stdout_log "Python Version Selected: python${python_version}"
	    break
        fi
    done
    init_venv_python
else
    stdout_log "INFO: using exising virtual environment"
    debugging "Upgrade pip"
    if ! (${venv_python} -m pip install pip --upgrade > /dev/null 2>&1); then assert "Pip upgrade failed"; fi
fi

stdout_log "Installing Platform9 Express Management Suite"
if ! (${venv_python} -m pip install -e  ${wizard_url} > /dev/null 2>&1); then
    assert "Installation of Platform9 Express Wizard Failed"; fi
if ! (wizard --help > /dev/null 2>&1); then assert "Unable to launch Platform9 Wizard"; fi
if [ ! -f ${wizard} ]; then
    if ! (ln -s ${wizard_entrypoint} ${wizard} > /dev/null 2>&1); then
	assert "failed to create Express-Wizard symlink: ${wizard_entrypoint} ${wizard}"; fi
fi
stdout_log "Installing Platform9 Express Management Environment"
if ! (express init > /dev/null 2>&1); then assert "Initialization of Platform9 Express-CLI Failed"; fi
if [ ! -f ${cli} ]; then
    if ! (ln -s ${cli_entrypoint} ${cli} > /dev/null 2>&1); then
	assert "failed to create Express-CLI symlink: ${cli_script}"; fi
fi

# Merge runtime arguments
if [[ -n ${wizard_branch} ]]; then args+=" --branch ${wizard_branch}";fi
if [[ -n ${test_wizard} ]]; then args+=" ${test_wizard}";fi
if [[ -n ${run_local} ]]; then args+=" ${run_local}";fi
if [[ -n ${config_file} ]]; then args+=" --config ${config_file}";fi
if [[ -n ${debug_flag} ]]; then 
    if [[ ${debug_flag} == "-d" || ${debug_flag} == "--debug"  ]]; then
	args+=" --debug 1"
    else
	args+=" --debug ${debug_flag}"
    fi
fi

if [[ -d "${pf9_bin}" ]]; then
    if ! echo "$PATH" | grep -q "${pf9_bin}"; then
        export PATH="${pf9_bin}:$PATH"
    fi
fi
debugging "Wizard Launch Command: ${wizard}${args}"
launch_wizard="(${venv_python} ${wizard}${args} -t)"

#launch_wizard="(. ${venv_activate} && ${venv_python} ${wizard_script}${args})"
