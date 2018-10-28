Uplink Encoding / Decoding
==========================

Include
-------
Include the uplink header for uplink functionality:

.. code-block:: c

	#include <uplink.h>

Functions
---------
.. doxygenfunction:: sfx_uplink_encode
.. doxygenfunction:: sfx_uplink_decode

Inputs and outputs
------------------
.. doxygenstruct:: sfx_ul_plain
	:members:
.. doxygenstruct:: sfx_ul_encoded
	:members:

Errors
------
.. doxygenenum:: sfx_ule_err
.. doxygenenum:: sfx_uld_err

Preamble
--------
The encoding / decoding functions handle uplinks excluding the preamble.
However, the preamble content can be obtained from the following array:

.. doxygenvariable:: SFX_UL_PREAMBLE
.. doxygendefine:: SFX_UL_PREAMBLELEN_NIBBLES
