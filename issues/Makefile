SOURCE=src
INCLUDE=include
BUILD=build
LIBRARY= -lcmocka -lcapstone

all:
	rm -rf $(BUILD)
	mkdir $(BUILD)
	$(CC) -g $(SOURCE)/*.c -I$(INCLUDE) -o $(BUILD)/issues $(LIBRARY)
clean:
	rm -rf $(BUILD)
