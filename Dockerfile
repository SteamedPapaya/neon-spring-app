# OpenJDK 17을 베이스 이미지로 사용합니다.
FROM openjdk:17-jdk-slim

# 애플리케이션 JAR 파일을 컨테이너로 복사합니다.
ARG JAR_FILE=build/libs/*.jar
COPY ${JAR_FILE} app.jar

# 컨테이너에서 애플리케이션을 실행합니다.
ENTRYPOINT ["java", "-jar", "/app.jar"]

# 애플리케이션이 사용하는 포트를 설정합니다.
EXPOSE 8080