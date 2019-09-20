#!/bin/bash
#
# Copyright 2019 Aletheia Ware LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e
set -x

if [ -d out ]; then
    rm -r out
fi
mkdir -p out/code
mkdir -p out/test

SOURCES=(
    source/com/aletheiaware/finance/utils/FinanceUtils.java
)

PROTO_SOURCES=(
    source/com/aletheiaware/finance/FinanceProto.java
)

# Compile code
javac -cp ../AliasJava/out/AliasJava.jar:../BCJava/out/BCJava.jar:../JavaCommon/libs/protobuf-java-3.9.1.jar ${SOURCES[*]} ${PROTO_SOURCES[*]} -d out/code
jar cvf out/FinanceJava.jar -C out/code .


TEST_SOURCES=(
    test/source/com/aletheiaware/finance/AllTests.java
    test/source/com/aletheiaware/finance/utils/FinanceUtilsTest.java
)

# Compile tests
javac -cp ../AliasJava/out/AliasJava.jar:../BCJava/out/BCJava.jar:../JavaCommon/libs/protobuf-java-3.9.1.jar:../JavaCommon/libs/junit-4.12.jar:../JavaCommon/libs/hamcrest-core-2.1.jar:../JavaCommon/libs/mockito-all-1.10.19.jar:out/FinanceJava.jar ${TEST_SOURCES[*]} -d out/test
jar cvf out/FinanceJavaTest.jar -C out/test .

# Run tests
java -cp ../AliasJava/out/AliasJava.jar:../BCJava/out/BCJava.jar:../JavaCommon/libs/protobuf-java-3.9.1.jar:../JavaCommon/libs/junit-4.12.jar:../JavaCommon/libs/hamcrest-core-2.1.jar:../JavaCommon/libs/mockito-all-1.10.19.jar:out/FinanceJava.jar:out/FinanceJavaTest.jar org.junit.runner.JUnitCore com.aletheiaware.finance.AllTests

# Checkstyle
java -jar ../JavaCommon/libs/checkstyle-8.24-all.jar -c ../checkstyle.xml ${SOURCES[*]} ${TEST_SOURCES[*]} > out/style || true
