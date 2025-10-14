# 🚀 快速开始指南

## 📝 项目说明

这个项目已经为你准备好了所有必要的文件！它可以自动化处理 JSON 文件，为每个条目添加时间戳并使用 RSA 加密。

## ✅ 已完成的准备工作

1. ✅ Python 处理脚本 (`process_json.py`)
2. ✅ GitHub Actions 工作流 (`.github/workflows/process-json.yml`)
3. ✅ 示例 JSON 数据文件 (`data.json`)
4. ✅ 依赖文件 (`requirements.txt`)
5. ✅ RSA 密钥对已生成（`public_key.pem` 和 `private_key.pem`）

## 🎯 下一步操作

### 步骤 1: 初始化 Git 仓库（如果还没有）

```bash
git init
git add .
git commit -m "Initial commit: JSON 处理和加密系统"
```

### 步骤 2: 推送到 GitHub

```bash
# 创建 GitHub 仓库后，添加远程仓库
git remote add origin https://github.com/your-username/your-repo.git
git branch -M main
git push -u origin main
```

### 步骤 3: 配置 GitHub Actions 权限

1. 进入你的 GitHub 仓库
2. 点击 **Settings** → **Actions** → **General**
3. 找到 **Workflow permissions**
4. 选择 **Read and write permissions**
5. 勾选 **Allow GitHub Actions to create and approve pull requests**
6. 点击 **Save**

### 步骤 4: 保存公钥到 GitHub Secrets（可选但推荐）

1. 打开文件 `public_key.pem` 并复制全部内容
2. 进入仓库的 **Settings** → **Secrets and variables** → **Actions**
3. 点击 **New repository secret**
4. 名称输入: `RSA_PUBLIC_KEY`
5. 值粘贴: 公钥内容
6. 点击 **Add secret**

### 步骤 5: 运行工作流

#### 方式 1: 手动触发

1. 进入仓库的 **Actions** 标签页
2. 选择 "处理 JSON 文件并加密" 工作流
3. 点击 **Run workflow** 按钮
4. 输入 JSON 文件路径（默认: `data.json`）
5. 点击绿色的 **Run workflow** 按钮

#### 方式 2: 自动触发

- **定时触发**: 每天 UTC 00:00 自动运行
- **文件变化触发**: 修改并推送 `data.json` 或其他 `.json` 文件时自动运行

```bash
# 修改 data.json 后
git add data.json
git commit -m "Update JSON data"
git push
```

## 🧪 本地测试

在推送到 GitHub 之前，可以先本地测试：

```bash
# 安装依赖
pip install -r requirements.txt

# 运行脚本
python process_json.py data.json

# 查看处理结果
type data_processed.json
```

## 📊 查看处理结果

处理完成后的 JSON 文件包含：
- ✅ **timestamp**: 每个条目的 UTC 时间戳
- ✅ **encrypted_data**: RSA 加密的 base64 字符串
- ✅ **data_hash**: 大数据的加密哈希

示例：
```json
{
  "users": [
    {
      "id": 1,
      "name": "张三",
      "timestamp": "2025-10-13T07:48:29.675952Z",
      "encrypted_data": "IRvCWZ9UZYuPAYHjSoqU9xhQy9J..."
    }
  ]
}
```

## 🔐 密钥管理重要提示

- ⚠️ **不要提交** `private_key.pem` 到仓库（已在 `.gitignore` 中排除）
- ✅ **可以提交** `public_key.pem` 到仓库（仅用于加密）
- 💡 **推荐做法**: 将公钥保存到 GitHub Secrets

## 🛠️ 自定义配置

### 修改处理逻辑

编辑 `process_json.py` 中的 `process_json_data` 方法：

```python
def process_json_data(self, data):
    # 在这里添加你的自定义逻辑
    # 例如：添加其他字段、过滤数据等
    pass
```

### 修改触发时间

编辑 `.github/workflows/process-json.yml`：

```yaml
schedule:
  - cron: '0 */6 * * *'  # 每 6 小时运行一次
```

### 处理多个 JSON 文件

可以在工作流中添加多个步骤：

```yaml
- name: 处理文件1
  run: python process_json.py file1.json

- name: 处理文件2
  run: python process_json.py file2.json
```

## ❓ 常见问题

### Q: 工作流运行失败怎么办？

A: 检查以下几点：
1. 确保 Actions 权限设置正确（Read and write permissions）
2. 查看 Actions 标签页的运行日志
3. 确保 `data.json` 文件存在且格式正确

### Q: 如何解密加密的数据？

A: 使用 `private_key.pem` 和 Python 脚本：

```python
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64

# 加载私钥
with open('private_key.pem', 'rb') as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

# 解密数据
encrypted_data = "你的加密字符串..."
decrypted = private_key.decrypt(
    base64.b64decode(encrypted_data),
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print(decrypted.decode('utf-8'))
```

### Q: 可以处理其他格式的文件吗？

A: 当前版本专注于 JSON 文件。如果需要处理其他格式（如 CSV、XML），可以修改 `process_json.py` 来支持。

## 📚 更多信息

查看完整文档: [README.md](README.md)

## 🎉 开始使用

现在你已经准备好了！执行步骤 1-5，让你的自动化 JSON 处理系统运行起来！
