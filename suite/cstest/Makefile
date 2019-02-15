SOURCE=src
INCLUDE=include
BUILD=build
LIBRARY= -lcmocka -lcapstone

all:
	rm -rf $(BUILD)
	mkdir $(BUILD)
	$(CC) $(SOURCE)/*.c -I$(INCLUDE) -o $(BUILD)/cstest $(LIBRARY)
cstest:
	$(BUILD)/cstest -d ../MC	
clean:
	rm -rf $(BUILD)
