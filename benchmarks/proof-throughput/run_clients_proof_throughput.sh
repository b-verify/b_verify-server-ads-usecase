#!/bin/bash
export MAVEN_OPTS="-Xmx25G"
mvn exec:java -Dexec.mainClass=bench.ProofGenerationThroughputBenchmark -Dexec.args="127.0.0.1 1099 CLIENT"
