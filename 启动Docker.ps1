$ErrorActionPreference = "Stop"

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "未检测到 Docker。请先安装并启动 Docker Desktop。"
}

docker compose up --build -d
if ($LASTEXITCODE -ne 0) {
    throw "Docker Compose 启动失败。"
}

Write-Host "AI-LogInsight 已启动: http://localhost:8080"
Write-Host "查看日志: docker compose logs -f"
Write-Host "停止服务: docker compose down"
