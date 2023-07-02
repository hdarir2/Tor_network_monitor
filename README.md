Readme
======

Simple Bandwidth Scanner (called `sbws`) is a Tor bandwidth scanner that
generates bandwidth files to be used by Directory Authorities.

The scanner measures the bandwidth of each relay in the Tor network
(except the directory authorities) by creating a two hops circuit
with the relay. It then measures the bandwidth by downloading data
from a destination Web Server and stores the measurements.

The generator read the measurements, aggregates, filters and
scales them using different scaling method. The scaling methods offered by this version are Torflow,
MLEFlow [1] and the newest Probabilistic programming algorithm [2].
Then it generates a bandwidth list file that is read
by a directory authority to report relays’ bandwidth in its vote.

The clientbuilder helps in creating virtual clients in a virtual Tor network, i.e. shadow.

**WARNING**: This software is intended to be run by researchers using a test
Tor network, such as chutney or shadow, or by the Tor bandwidth authorities
on the public Tor network.
Please do not run this software on the public Tor network unless you are one
of the Tor bandwidth authorities, to avoid creating unnecessary traffic.


Installing
------------

Command installation:

cd sbws
python3 setup.py install

See [./INSTALL.rst](INSTALL.rst)

## Authors

Hussein Darir,
PhD in mechanical engineering,
University of Illinois Urbana-Champaign.

## References

[1]: Darir, H., Sibai, H., Cheng, C.-Y., Borisov, N., Dullerud, G., & Mitra, S. (2022). Mleflow: Learning from history to improve load
balancing in tor. In Proceedings on privacy enhancing technologies (Vol. 2022, pp. 75–104). 􀃮 doi:doi:10.2478/popets-2022-0005

[2]: Darir, H., Borisov, N., & Dullerud, G. (2023). Probflow : Using probabilistic programming in anonymous communication networks.
In Network and distributed system security (ndss) symposium. 􀃮 doi:doi:10.14722/ndss.2023.24140
