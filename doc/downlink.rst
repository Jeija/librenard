Downlink Encoding / Decoding
============================

Functions
---------
.. doxygenfunction:: sfx_downlink_encode
.. doxygenfunction:: sfx_downlink_decode

Inputs and outputs
------------------
.. doxygenstruct:: sfx_dl_plain
	:members:
.. doxygenstruct:: sfx_dl_encoded
	:members:

Preamble
--------
The encoding / decoding functions handle downlinks excluding the preamble.
However, the preamble content can be obtained from the following array:

.. doxygenvariable:: SFX_DL_PREAMBLE
.. doxygendefine:: SFX_DL_PREAMBLELEN
