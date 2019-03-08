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



Configure
---------
The Helios Protocol consensus mechanism is partially based on PoS. This requires that all nodes are associated
with a wallet address that has a non-zero stake in order to run. So at this point, you have to configure
the node software to use your wallet as a source of coins to stake.

1)  Create keystore file. This is an encrypted file that stores your private key. You will be able to create this
    with our wallet when it is released. But for now, you can just create a new wallet using
    `MyEtherWallet <http://myetherwallet.com>`_, then save the wallet file. This file will work with
    Helios Protocol.
2)  Place keystore file within the directory helios/keystore
3)  Configure node to use your keystore file. Copy helios/helios_config.template.py to helios/helios_config.py.
    Then edit the new file and tell it the filename of your keystore file to use.

Open Ports in Firewall
----------------------
The node software needs to have an open path for communication with other nodes on the network. If you
have firewall software enabled, such as iptables, then you might have to open some ports to ensure this.
The default installation of Ubuntu and Debian probably already have the ports open. Other distros such as Centos
likely have most ports closed by default.

Debian and Ubuntu

.. code:: bash

    $ sudo iptables -I INPUT -p tcp -m tcp --dport 30303 -j ACCEPT
    $ sudo iptables -I INPUT -p tcp -m tcp --dport 30304 -j ACCEPT
    $ sudo iptables-save

Centos 7

.. code:: bash

    $ sudo firewall-cmd --permanent –zone=public --add-port=30303/tcp
    $ sudo firewall-cmd --permanent –zone=public --add-port=30304/tcp
    $ sudo firewall-cmd --reload


Start the node
--------------

.. code:: bash

    $ helios

Then enter your keystore password when prompted. This password is never saved, it is only used to initially decrypt your keystore
file.


This document is still a work in progress. More details will come soon.
