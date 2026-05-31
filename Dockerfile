FROM eclipse-temurin:21-jre-alpine

WORKDIR /app

COPY target/authservice-0.0.1-SNAPSHOT.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-Dspring.profiles.active=docker", "-jar", "app.jar"]
