# Manga Hub

Este é um site simples para postar livros de mangá, criado com Flask e SQLite. O projeto inclui páginas para listar mangás, adicionar novos e visualizar detalhes.

## Estrutura

- `app.py` - aplicativo Flask principal
- `requirements.txt` - dependências Python
- `templates/` - HTML com Jinja2
- `static/` - arquivos estáticos (CSS, imagens, etc.)
- `manga.db` - banco de dados SQLite (gerado automaticamente)

## Configuração

1. Crie e ative um ambiente virtual Python:
   ```bash
   python -m venv venv
   venv\Scripts\activate  # Windows
   ```
2. Instale as dependências (Flask, SQLAlchemy, etc.):
   ```bash
   pip install -r requirements.txt
   ```
   > Se você vir erros como `ModuleNotFoundError: No module named 'flask_sqlalchemy'`, execute este comando no ambiente ativo e tente novamente.
3. Execute o aplicativo:
   ```bash
   python app.py
   ```
4. Acesse `http://127.0.0.1:5000` no navegador.

## Uso

- O site agora possui **temática anime** com cores vibrantes, fontes estilo game e animações.
- Para postar mangás, é necessário fazer login como administrador.
- Qualquer usuário pode se registrar e entrar; existe uma opção de marcar a conta como **tradutor** no registro. Contas de tradutor podem ser comentadas no site (ou usadas para efeitos especiais se você implementar algo depois).
- Para cada mangá você pode enviar até **320 arquivos JPG, PNG ou GIF** que representem as páginas; a ordem é a mesma em que você selecionou/desenhou no formulário. A primeira imagem também é usada como capa. Tradutores (ou administradores) podem anexar um PDF com as imagens completas; os arquivos ficam em `static/uploads` e são exibidos/encadeados na página de detalhes.
- A primeira vez que você iniciar o programa será criado um usuário administrador padrão `admin` com senha `admin`.
  > **Troque essa senha imediatamente!**
- Acesse `/login` e informe suas credenciais.
- Depois de logado como administrador, você pode excluir qualquer mangá na página de detalhes.
- Usuários registrados têm acesso a uma aba "Meus Favoritos" para ver e remover suas escolhas.
- Uma vez logado como administrador, o link "Postar Mangá" aparecerá na barra de navegação.
- Os mangás serão listados na página inicial e cada título leva à página de detalhes.

## Configuração de conta

O arquivo `app.py` contém a função `ensure_admin()` que cria um usuário com `username='admin'` e `password='admin'` quando não existe nenhum administrador no banco. Para alterar ou criar contas adicionais, use o console Python ou implemente uma interface de gerenciamento.

## Atualização de esquema

Se você já tiver um banco `manga.db` criado antes de fevereiro de 2026, ele não terá o campo `image_filename`. Apague o arquivo ou execute uma migração para adicionar a coluna. O código cria a pasta `static/uploads` automaticamente.

## Nota

Este exemplo agora inclui autenticação simples com Flask-Login. Para uso em produção, você deve:

1. Definir uma `secret_key` segura e não comitar no repositório.
2. Usar hashing forte e permitir registro/recuperação de senha.
3. Mudar `debug=False` e utilizar um servidor WSGI.
4. Usar HTTPS, controle de sessão, e banco de dados mais robusto, entre outros.
