.. currentmodule:: aiob2

API Reference
=============
The following content outlines the API of aiob2.

Clients
-------

Client
~~~~~~
.. autoclass:: Client
    :members:

aiob2 Models
--------------

Models are classes that are received from Backblaze, and are not intended to be created by users of the library.

.. danger::

    The classes listed below are **not intended to be created by users** and are also **read-only**.

    For example, this means that you should not make your own :class:`File` instances nor should you modify the :class:`File`
    instance yourself.

    If you want to get one of these model classes instances, they'd have to be through the API or a property of another
    object that had been fetched already.

Files
~~~~~
.. autoclass:: File()

.. autoclass:: DeletedFile()

.. autoclass:: DownloadedFile()
