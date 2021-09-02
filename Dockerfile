FROM mcr.microsoft.com/dotnet/sdk:3.1 AS buildimage
WORKDIR /app
COPY ./ ./
RUN dotnet restore Ids/Ids.csproj
RUN dotnet publish Ids/Ids.csproj --no-restore -c Release -o ./out -p:PublishTrimmed=true --self-contained true -r linux-musl-x64

FROM mcr.microsoft.com/dotnet/aspnet:3.1
WORKDIR /app
COPY --from=buildimage /app/out ./
EXPOSE 80
HEALTHCHECK --interval=5m --timeout=3s CMD curl -f http://localhost/health || exit 1
ENTRYPOINT ["dotnet", "Ids.dll"]