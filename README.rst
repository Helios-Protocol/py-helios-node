====================
Helios Protocol Node
====================

.. image:: https://img.shields.io/badge/python-3.6-blue.svg
    :target: https://www.python.org/downloads/release/python-360/
    :alt: Python3.6


This is the beta stage of the HeliosProtocol node. It is currently under active development and is not yet complete.

Install
-------


Py-helios-node install instructions:

1)  Make sure you have the correct version of python installed.
    The version is listed at the top of this document. Caution:
    do not upgrade your system python from 2 to 3 as this can cause
    massive problems. Instead, we recommend installing a new version
    of python using `pyenv <https://github.com/pyenv/pyenv>`_. To install
    pyenv, use the setup script found `here <https://github.com/pyenv/pyenv-installer>`_.
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

    3)  Reload .bashrc

        .. code:: bash

            $ source ~/.bashrc

    4)  Install python 3.6

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


5)  Install the Helios Node

    .. code:: bash

        $ pip3 install -e .

6)  Ensure that the slow version of RLP is uninstalled, and install
    a fresh copy of the fast one. This will force all external libraries
    that use RLP to switch to the fast one.

    .. code:: bash

        $ pip3 uninstall rlp
        $ pip3 uninstall rlp-cython
        $ pip3 install rlp-cython


Further instructions coming soon.
