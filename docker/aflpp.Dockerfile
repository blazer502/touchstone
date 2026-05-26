# AFL++ — built from the official versioned image.
ARG AFLPP_VERSION=4.21c
FROM aflplusplus/aflplusplus:${AFLPP_VERSION}

CMD ["afl-fuzz", "-h"]
