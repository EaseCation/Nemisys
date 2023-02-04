#FROM bellsoft/liberica-openjre-alpine-musl:8 AS build
#
#WORKDIR /app
#
#COPY mvnw ./
#COPY .mvn/ .mvn
#
#COPY pom.xml ./
#RUN ./mvnw -B dependency:resolve
#
#COPY src ./src
#RUN ./mvnw -B package

FROM bellsoft/liberica-openjre-alpine-musl:8 AS run

WORKDIR /nemisys

#COPY --from=build /app/target/nemisys.jar ./
COPY target/nemisys.jar ./

EXPOSE 19132/udp 10305/tcp

CMD ["java", "-jar", "nemisys.jar"]
