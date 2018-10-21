``librenard`` documentation
===========================
.. figure:: _static/logo.svg
   :width: 200 px
   :align: right

``librenard`` is an open source library for encoding and decoding Sigfox uplinks and downlinks.
A command line interface to ``librenard`` is provided by |renard|_.
``librenard`` does not implement physical layer (de)modulation, please refer to |renard-phy|_ for that instead.

.. |renard| replace:: ``renard``
.. _renard: https://github.com/Jeija/renard

.. |renard-phy| replace:: ``renard-phy``
.. _renard-phy: https://github.com/Jeija/renard-phy

The following API documentation will give you an overview of how to use ``librenard``.
For a deeper understanding of the inner workings of ``librenard``, please refer to the Bachelor's Thesis
*Reverse Engineering of the Sigfox Radio Protocol and Implementation of an Alternative Sigfox Network Stack*.

.. toctree::
        :maxdepth: 2
        :caption: Contents:

        uplink
        downlink
	common

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
