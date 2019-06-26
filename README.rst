====================
Helios Protocol Node
====================

.. image:: https://img.shields.io/badge/python-3.6-blue.svg
    :target: https://www.python.org/downloads/release/python-360/
    :alt: Python3.6


This is the beta stage of the HeliosProtocol node. It is currently under active development and is not yet complete.

Install
-------

If you just installed Debian linux, and you are a beginner linux user, check the "First time Debian user notes" section at the bottom first


Py-helios-node install instructions:

1)  Make sure you have the correct version of python installed.
    The version is listed at the top of this document. Caution:
    do not upgrade your system python from 2 to 3 as this can cause
    massive problems. Instead, we recommend installing a new version
    of python using `pyenv <https://github.com/pyenv/pyenv>`_. To install
    pyenv, use the setup script found `here <https://github.com/pyenv/pyenv-installer>`_.
    For completeness, we will summarize the current setup steps here:

    1)  Prerequisites

        .. code:: bash

            $ sudo apt install git
            $ sudo apt install curl

        or for centos:

        .. code:: bash

            $ sudo yum install git
            $ sudo yum install curl

    2)  Install

        .. code:: bash

            $ curl -L https://github.com/pyenv/pyenv-installer/raw/master/bin/pyenv-installer | bash

    3)  Edit .bashrc

        .. code:: bash

            $ vi ~/.bashrc

        add the lines

        .. code:: bash

            export PATH="~/.pyenv/bin:$PATH"
            eval "$(pyenv init -)"
            eval "$(pyenv virtualenv-init -)"

    4)  Reload .bashrc

        .. code:: bash

            $ source ~/.bashrc

    5)  Install python 3.6

        First, make sure you have some required packages installed:

        .. code:: bash

            $ sudo apt install build-essential
            $ sudo apt install zlib1g
            $ sudo apt install zlib1g-dev
            $ sudo apt install libssl-dev

        Then install python 3.6 using the following command

        .. code:: bash

            $ pyenv install 3.6.5

        If you get any warnings, it is usually ok. But if you get an error at this step, it probably means
        you didn't have a required package installed. Read the error message, and it will tell you which
        package you need to install. Install the missing package using sudo apt install ... Then after that,
        run the above command again. Make sure it succeeds without an error before moving on.


2)  Clone this repo

    .. code:: bash

        $ cd ~/
        $ git clone https://github.com/Helios-Protocol/py-helios-node


3)  Set python environment

    .. code:: bash

        $ cd py-helios-node
        $ pyenv local 3.6.5


4)  Install the Helios Node

    .. code:: bash

        $ pip3 install -e .

5)  Ensure that the slow version of RLP is uninstalled, and install
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
3)  Configure node to use your keystore file. Copy helios/helios_config_template.py to helios/helios_config.py.
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

    $ python ~/py-helios-node/helios/main.py

Then enter your keystore password when prompted. This password is never saved, it is only used to initially decrypt your keystore
file.


This document is still a work in progress. More details will come soon.


Node troubleshooting
--------------------
If your node shuts down unexpectedly, it may leave dangling processes and ipc sockets
which will give you problems when you try to start
it again. If this happens, run this command to force close all previous node processes:

.. code:: bash

    $ python ~/py-helios-node/helios/main.py fix-unclean-shutdown

After this has finished running, you can then run the node software normally again.

If you ever want to check the logs, you can find them at ~/.local/share/helios/mainnet/logs

First time Debian user notes
----------------------------

If you just installed debian linux, you will need to give your personal user sudoer privileges. This is
required for the above installation steps that have sudo at the beginning. Do this by running
the following commands:

.. code:: bash

        $ su

Type in your root password when prompted, then:

.. code:: bash

        $ usermod -aG sudo username

Where "username" is replaced with the name of your personal user that you want to add to the sudoers.

Then, logout and log back in. After this you will have sodoer privileges.
