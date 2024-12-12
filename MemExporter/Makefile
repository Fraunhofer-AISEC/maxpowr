#
# Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#

include buildenv.mk

.PHONY: all target run
all: .config_$(Build_Mode)_$(SGX_ARCH)
ifneq ($(OUTPUT_DIR),)
	$(shell mkdir $(OUTPUT_DIR))
endif
	@$(MAKE) target

ifeq ($(Build_Mode), HW_RELEASE)
target:  $(App_Name) $(Enclave_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(App_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
target: $(App_Name) $(Signed_Enclave_Name)
ifeq ($(Build_Mode), HW_DEBUG)
	@echo "The project has been built in debug hardware mode."
else ifeq ($(Build_Mode), SIM_DEBUG)
	@echo "The project has been built in debug simulation mode."
else ifeq ($(Build_Mode), HW_PRERELEASE)
	@echo "The project has been built in pre-release hardware mode."
else ifeq ($(Build_Mode), SIM_PRERELEASE)
	@echo "The project has been built in pre-release simulation mode."
else
	@echo "The project has been built in release simulation mode."
endif
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(App_Name)
	@echo "RUN  >>  $(App_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

.config_$(Build_Mode)_$(SGX_ARCH):
	@rm -rf $(OUTPUT_DIR)
	@rm -f .config_* App/Enclave_u.* Enclave/Enclave_t.* Enclave/$(INJECTOR_TARGET)_gen.*
	@find . -name "*.o" -type f -delete
	@touch .config_$(Build_Mode)_$(SGX_ARCH)

######## App Objects ########

App/Enclave_u.h: $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd App && $(SGX_EDGER8R) --untrusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "$(BOLD)GEN  >>$(NORM)  $@"

App/Enclave_u.c: App/Enclave_u.h

$(OUTPUT_DIR_NAME)/Enclave_u.o: App/Enclave_u.c
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(App_C_Flags) -c $< -o $@
	@echo "$(BOLD)CXX  <<$(NORM)  $<"

App/%.o: App/%.cpp  App/Enclave_u.h
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(App_Cpp_Flags) -c $< -o $@
	@echo "$(BOLD)CXX  <<$(NORM)  $<"

$(App_Name): $(OUTPUT_DIR_NAME)/Enclave_u.o $(App_Cpp_Objects)
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "$(BOLD)LINK >>$(NORM)  $@"
	@mv $@ $(OUTPUT_DIR)
	@mv $(App_Cpp_Objects) $(OUTPUT_DIR)

######## Enclave Objects ########

Enclave/$(INJECTOR_TARGET)_gen.h: Enclave/Enclave_t.h
	@python3 $(INJECTOR) --header Enclave/$(INJECTOR_TARGET).h --source Enclave/$(INJECTOR_TARGET).cpp --payload $(INJECTOR_PAYLOAD)
	@echo "$(BOLD)GEN  >>$(NORM)  $@"

Enclave/$(INJECTOR_TARGET)_gen.cpp: Enclave/$(INJECTOR_TARGET)_gen.h

$(OUTPUT_DIR_NAME)/$(INJECTOR_TARGET)_gen.o: Enclave/$(INJECTOR_TARGET)_gen.cpp
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(Enclave_Cpp_Flags) $(SGX_INTEL_ASM_FLAG) -c $< -o $@
	@echo "$(BOLD)CXX  <<$(NORM)  $<"

Enclave/Enclave_t.h: $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd Enclave && $(SGX_EDGER8R) --trusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "$(BOLD)GEN  >>$(NORM)  $@"

Enclave/Enclave_t.c: Enclave/Enclave_t.h

$(OUTPUT_DIR_NAME)/Enclave_t.o: Enclave/Enclave_t.c
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(Enclave_C_Flags) -c $< -o $@
	@echo "$(BOLD)CXX  <<$(NORM)  $<"

Enclave/%.o: Enclave/%.cpp Enclave/Enclave_t.h Enclave/$(INJECTOR_TARGET)_gen.h
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "$(BOLD)CXX  <<$(NORM)  $<"

$(Enclave_Name): $(OUTPUT_DIR_NAME)/$(INJECTOR_TARGET)_gen.o $(OUTPUT_DIR_NAME)/Enclave_t.o $(Enclave_Cpp_Objects)
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "$(BOLD)LINK >>$(NORM)  $@"
	@mv $@ $(OUTPUT_DIR)
	@mv $(Enclave_Cpp_Objects) $(OUTPUT_DIR)

$(Signed_Enclave_Name): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key Enclave/Enclave_private_test.pem -enclave $(OUTPUT_DIR)/$(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "$(BOLD)SIGN >>$(NORM)  $@"
	@mv $@ $(OUTPUT_DIR)

.PHONY: clean
clean:
	@rm -rf $(OUTPUT_DIR)
	@rm -f .config_*  App/Enclave_u.* Enclave/Enclave_t.* Enclave/$(INJECTOR_TARGET)_gen.*
	@find . -name "*.o" -type f -delete
