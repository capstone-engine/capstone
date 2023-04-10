SOURCE = src
INCLUDE = include ../../include
BUILD = build
LIBRARY = -lcmocka -lcapstone -L../..

all:
	rm -rf $(BUILD)
	mkdir $(BUILD)
	$(CC) $(SOURCE)/*.c $(INCLUDE:%=-I %) -o $(BUILD)/cstest $(LIBRARY)
cstest:
	$(BUILD)/cstest -d ../MC	
clean:
	rm -rf $(BUILD)
