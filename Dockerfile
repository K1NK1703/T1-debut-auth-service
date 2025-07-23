FROM openjdk:23-jdk-slim as build

WORKDIR /app

COPY mvnw .
COPY .mvn .mvn

COPY pom.xml .
COPY src ./src

RUN ./mvnw clean package -DskipTests

FROM openjdk:23-jdk-slim

WORKDIR /app

COPY --from=build /app/target/*.jar app.jar

RUN java -Djarmode=layertools -jar app.jar extract

ENTRYPOINT ["java", "-jar", "app.jar"]