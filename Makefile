# Makefile

# 컴파일러 설정
CC = g++
CFLAGS = -std=c++11 -Wall
LIBS = -lssl -lcrypto

# 빌드 대상 설정
TARGET = test

# 소스 파일 및 객체 파일 목록 설정
SRCS = ProtocolTest.cpp Paillier/EqualityTest_Paillier.cpp Paillier/Paillier.cpp
OBJS = $(SRCS:.cpp=.o)

# 인클루드 디렉토리 설정
INC_DIRS = -I. -IPaillier

# 기본 빌드 명령
all: $(TARGET)

# 목표 파일 빌드 명령
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(INC_DIRS) -o $(TARGET) $(OBJS) $(LIBS)

# 개별 소스 파일 컴파일 명령
%.o: %.cpp
	$(CC) $(CFLAGS) $(INC_DIRS) -c $< -o $@

# 의존성 관계 설정
ProtocolTest.o: ProtocolTest.cpp Paillier/EqualityTest_Paillier.h
	$(CC) $(CFLAGS) $(INC_DIRS) -c ProtocolTest.cpp -o ProtocolTest.o

EqualityTest_Paillier.o: Paillier/EqualityTest_Paillier.cpp Paillier/EqualityTest_Paillier.h Paillier/Paillier.h
	$(CC) $(CFLAGS) $(INC_DIRS) -c Paillier/EqualityTest_Paillier.cpp -o EqualityTest_Paillier.o

Paillier.o: Paillier/Paillier.cpp Paillier/Paillier.h
	$(CC) $(CFLAGS) $(INC_DIRS) -c Paillier/Paillier.cpp -o Paillier.o

# 불필요한 파일 정리 명령
clean:
	rm -f $(OBJS) $(TARGET)
