# JSON 自动处理与加密系统

这个项目使用 GitHub Actions 自动从仓库读取 JSON 文件，为每个条目添加时间戳并使用 RSA 加密，然后更新回仓库。

## 📋 功能特性

- ✅ 自动读取 JSON 文件
- ✅ 遍历 JSON 内容并添加时间戳
- ✅ 使用 RSA 公钥加密数据
- ✅ 自动提交并推送更改到仓库
- ✅ 支持手动触发、定时触发和文件变化触发
- ✅ 密钥管理和备份

## 🚀 快速开始

### 1. 本地测试

首先安装依赖：

```bash
pip install -r requirements.txt
```

然后运行脚本处理 JSON 文件：

```bash
python process_json.py data.json
```

这会：
- 生成 RSA 密钥对（如果不存在）
- 读取 `data.json`
- 为每个条目添加时间戳
- 使用 RSA 加密数据
- 保存处理后的文件

### 2. 在 GitHub Actions 中使用

#### 方法 1: 手动触发

1. 进入仓库的 **Actions** 标签页
2. 选择 "处理 JSON 文件并加密" 工作流
3. 点击 **Run workflow**
4. 输入要处理的 JSON 文件路径（默认: `data.json`）
5. 点击 **Run workflow** 开始执行

#### 方法 2: 定时自动触发

工作流配置为每天 UTC 时间 00:00 自动运行。

#### 方法 3: 文件变化触发

当你推送对 `data.json` 或其他 `.json` 文件的更改时，工作流会自动运行。

## 🔐 密钥管理

### 首次运行

首次运行时，脚本会自动生成 RSA 密钥对：
- `private_key.pem` - 私钥（用于解密，请妥善保管）
- `public_key.pem` - 公钥（用于加密，会提交到仓库）

### 保存私钥到 GitHub Secrets（推荐）

为了安全起见，建议将公钥保存到 GitHub Secrets：

1. 复制 `public_key.pem` 的内容
2. 进入仓库的 **Settings** → **Secrets and variables** → **Actions**
3. 点击 **New repository secret**
4. 名称: `RSA_PUBLIC_KEY`
5. 值: 粘贴公钥内容
6. 点击 **Add secret**

这样工作流会优先使用 Secrets 中的密钥。

### 使用自己的密钥

如果你已有 RSA 密钥对，可以：

```bash
python process_json.py data.json --public-key /path/to/your/public_key.pem
```

## 📁 文件结构

```
git-action/
├── .github/
│   └── workflows/
│       └── process-json.yml    # GitHub Actions 工作流配置
├── process_json.py              # Python 处理脚本
├── requirements.txt             # Python 依赖
├── data.json                    # 示例 JSON 数据
├── public_key.pem              # RSA 公钥（自动生成）
├── private_key.pem             # RSA 私钥（自动生成，不要提交）
└── README.md                   # 本文档
```

## 🔧 自定义配置

### 修改触发条件

编辑 `.github/workflows/process-json.yml`：

```yaml
on:
  schedule:
    - cron: '0 */6 * * *'  # 改为每 6 小时运行一次
```

### 修改处理逻辑

编辑 `process_json.py` 中的 `process_json_data` 方法来自定义数据处理逻辑。

## 📊 查看结果

处理完成后，你可以：

1. 在 **Actions** 标签页查看运行日志
2. 在 **Summary** 中查看处理摘要
3. 下载 **Artifacts** 获取处理后的文件
4. 查看仓库中更新的 JSON 文件

## ⚠️ 注意事项

1. **私钥安全**: `private_key.pem` 包含敏感信息，不要提交到仓库。建议添加到 `.gitignore`。
2. **数据大小**: RSA 加密有大小限制（2048 位密钥最多加密 190 字节）。对于大数据，脚本会自动调整加密策略。
3. **权限配置**: 确保工作流有 `contents: write` 权限以推送更改。

## 🛠️ 故障排查

### 问题: 工作流无法推送更改

**解决方案**: 检查仓库设置
1. **Settings** → **Actions** → **General**
2. **Workflow permissions** 设置为 "Read and write permissions"

### 问题: 密钥加载失败

**解决方案**: 确保密钥格式正确（PEM 格式）

## 📝 示例输出

处理后的 JSON 会包含：

```json
{
  "users": [
    {
      "id": 1,
      "name": "张三",
      "timestamp": "2025-10-13T07:45:00Z",
      "encrypted_data": "base64_encoded_encrypted_string..."
    }
  ]
}
```