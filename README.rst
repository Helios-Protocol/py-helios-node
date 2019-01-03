====================
Helios Protocol Node
====================

[![Python 3.6](https://img.shields.io/badge/python-3.6-blue.svg)](https://www.python.org/downloads/release/python-360/)

This is the pre-alpha stage of the HeliosProtocol node. It is currently under active development and is not yet complete.

Install
-------


Py-helios-node install instructions:

1)  Make sure you have the correct version of python installed.
    The version is listed at the top of this document. Caution:
    do not upgrade your system python from 2 to 3 as this can cause
    massive problems. Instead, we recommend installing a new version
    of python using [pyenv](https://github.com/pyenv/pyenv). To install
    pyenv, use the setup script found [here](https://github.com/pyenv/pyenv-installer).
    For completeness, we will summarize the current setup steps here:

    1)  Install

        .. code:: bash

            $ curl -L https://github.com/pyenv/pyenv-installer/raw/master/bin/pyenv-installer | bash

    2)  Edit .bashrc

        .. code:: bash

            $ vi ~/.bashrc

        add the lines

        .. code:: bash

            export PATH="~/.pyenv/bin:$PATH"
            eval "$(pyenv init -)"
            eval "$(pyenv virtualenv-init -)"


    3)  Install python 3.6

        .. code:: bash

            $ pyenv install 3.6.5

2)  Install git

    .. code:: bash

                $ sudo apt install git

    or

    .. code:: bash

        $ sudo yum install git

3)  Clone this repo

    .. code:: bash

        $ git clone https://github.com/Helios-Protocol/py-helios-node


4)  Set python environment

    .. code:: bash

        $ cd py-helios-node
        $ pyenv local 3.6.5

5)  Install pandoc

    .. code:: bash

        $ sudo apt install pandoc

    or

    .. code:: bash

        $ sudo yum install pandoc


5)  Install the Helios Node

    .. code:: bash

        $ pip3 install -e .


Further instructions coming soon.
