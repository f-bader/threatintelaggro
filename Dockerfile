FROM mcr.microsoft.com/dotnet/sdk:10.0.403 AS build
WORKDIR /src
COPY src/ThreatIntelAggro/ThreatIntelAggro.csproj src/ThreatIntelAggro/
RUN dotnet restore src/ThreatIntelAggro/ThreatIntelAggro.csproj
COPY src/ThreatIntelAggro/ src/ThreatIntelAggro/
RUN dotnet publish src/ThreatIntelAggro/ThreatIntelAggro.csproj -c Release -o /app/publish --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:11.0.0 AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends libsqlite3-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app/publish .
RUN mkdir -p /data && chown $APP_UID:$APP_UID /data
ENV ASPNETCORE_HTTP_PORTS=8080
ENV AGGRO_DATA_DIR=/data
EXPOSE 8080
USER $APP_UID
ENTRYPOINT ["dotnet", "ThreatIntelAggro.dll"]
