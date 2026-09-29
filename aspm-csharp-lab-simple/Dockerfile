FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY src/AspmLab/AspmLab.csproj src/AspmLab/
RUN dotnet restore src/AspmLab/AspmLab.csproj
COPY . .
RUN dotnet publish src/AspmLab/AspmLab.csproj -c Release -o /app/publish --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app/publish .
# LAB-CONTAINER-001: intentionally runs as root so scanners can report it.
EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080
ENTRYPOINT ["dotnet", "AspmLab.dll"]
