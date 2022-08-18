TARGET = guest_preemption

$(TARGET).bin: $(TARGET).o $(TARGET).ld
	ld -T $(TARGET).ld -o $(TARGET).bin $(TARGET).o

$(TARGET).o: $(TARGET).S
	as -o $(TARGET).o $(TARGET).S

clean:
	rm -f *.o *.bin
