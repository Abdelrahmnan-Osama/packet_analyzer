#################################################################
#                  Packet Analyzer Build System                 #
#                                                               #
# This Makefile compiles both the main packet analyzer program  #
# and its test suite. It supports building, cleaning, and       #
# testing the application.                                      #
#################################################################

### COMPILER CONFIGURATION ###

# Specify the compiler to use (GNU C Compiler)
CC = gcc

# Compiler flags:
# -std=c11  : Use the C11 language standard
# -I.       : Include the current directory in header search path
CFLAGS = -std=c11 -I.

# Linker flags:
# -lpcap    : Link with libpcap (packet capture library)
LDFLAGS = -lpcap


### FILE DEFINITIONS ###

# Main application source files
SRC = main.c packet_parser.c main_utils.c

# Header files (for dependency tracking)
HEADERS = constants.h packet_parser.h main_utils.h

# Test suite source file
TEST_SRC = test_parser.c

# Output executables
TEST_EXE = test_parser         # Test runner executable
MAIN_EXE = packet_analyzer     # Main application executable


### BUILD TARGETS ###

# Default target - builds both main and test executables
all: $(MAIN_EXE) $(TEST_EXE)

# Rule for building main executable:
# Depends on all source and header files
# Links with libpcap for packet capture functionality
$(MAIN_EXE): $(SRC) $(HEADERS)
	$(CC) $(CFLAGS) $(SRC) -o $@ $(LDFLAGS)

# Rule for building test executable:
# Combines test code with packet parser implementation
$(TEST_EXE): $(TEST_SRC) packet_parser.c $(HEADERS)
	$(CC) $(CFLAGS) $(TEST_SRC) packet_parser.c -o $@


### UTILITY TARGETS ###

# Clean target - removes generated files
clean:
	rm -f $(MAIN_EXE) $(TEST_EXE) *.o *.txt *.log *.out

# Test target - builds and runs the test suite
test: $(TEST_EXE)
	./$(TEST_EXE)

# Run with arguments (needs sudo for packet capture)
run: $(MAIN_EXE)
	sudo ./$(MAIN_EXE) $(ARGS)

### PHONY TARGET DECLARATIONS ###
# These targets don't represent actual files

.PHONY: all clean test


#######################################################################
#                       USAGE INSTRUCTIONS                            #
#                                                                     #
# make                   : Build both main and test executables       #
# make packet_analyzer   : Build only the main program                #
# make test              : Build only the test suite                  #
# make test              : Build and run the test suite               #
# make run               : Build and run main program (use ARGS=...)  #
# make clean             : Remove all build artifacts                 #
#######################################################################
