# KLEE — use the upstream-published image matched to our LLVM version.
# The image already contains LLVM 14, STP, klee-uclibc, and libcxx so we avoid
# the ~1h source build.
ARG KLEE_VERSION=3.1
FROM klee/klee:${KLEE_VERSION}

CMD ["klee", "--version"]
