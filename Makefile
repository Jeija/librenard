TARGET := librenard.a
SRCDIR := src/
OBJDIR := obj/

CFLAGS := -Wall
LIBS :=

SRCS := $(wildcard  $(SRCDIR)*.c)
OBJS := $(addprefix $(OBJDIR),$(notdir $(SRCS:.c=.o)))

all: $(TARGET)

$(TARGET): $(OBJS)
	$(AR) cr $(TARGET) $(OBJS)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)%.o: $(SRCDIR)%.c $(OBJDIR)
	$(CC) -c $(LIBS) $(CFLAGS) $< -o $@

clean:
	$(RM) -r $(TARGET)
	$(RM) -r $(OBJDIR)
