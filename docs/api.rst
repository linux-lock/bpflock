.. _api_ref:

#############
API Reference
#############

************
Introduction
************

The Bpflock API is JSON based and provided by the ``bpflock`` daemon. The purpose
of the API is to provide visibility and control over the daemon.
All API calls affect only the resources managed by the
individual ``bpflock`` daemon serving the API. 

*********************
How to access the API
*********************

Example
-------

.. code-block:: shell-session

    # curl -v --no-buffer -XGET --unix-socket /var/run/bpflock/bpflock.sock 'http://localhost/v1/healthz' -H 'accept: application/json'
    [...]


************************
Compatibility Guarantees
************************

Bpflock is in experimental stage.


*************
API Reference
*************

See the still in development OpenAPI_ for more information.

.. _OpenAPI: ../api/v1/openapi.yaml
