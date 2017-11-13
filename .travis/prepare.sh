#!/bin/bash

git clone git://git.kernel.org/pub/scm/devel/sparse/chrisl/sparse.git
cd sparse && make CC=clang && make install && cd ..
