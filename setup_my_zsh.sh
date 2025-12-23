#!/bin/bash

echo "🚀 מתחילים בהתקנת oh-my-zsh אישית..."

# שלב 1: בטל משתנה סביבה אם קיים
unset ZSH

# שלב 2: התקן oh-my-zsh לתיקייה הביתית
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"

# שלב 3: התקנת תוספים
echo "📦 מתקין תוספים..."
git clone https://github.com/zsh-users/zsh-autosuggestions ~/.oh-my-zsh/custom/plugins/zsh-autosuggestions
git clone https://github.com/zsh-users/zsh-syntax-highlighting ~/.oh-my-zsh/custom/plugins/zsh-syntax-highlighting

# שלב 4: התקנת Powerlevel10k
echo "🎨 מתקין את Powerlevel10k..."
git clone --depth=1 https://github.com/romkatv/powerlevel10k.git ~/.oh-my-zsh/custom/themes/powerlevel10k

# שלב 5: עדכון ~/.zshrc
echo "🛠️ מגדיר את ~/.zshrc..."
cat > ~/.zshrc <<'EOF'
export ZSH="$HOME/.oh-my-zsh"
ZSH_THEME="powerlevel10k/powerlevel10k"
plugins=(git sudo zsh-autosuggestions zsh-syntax-highlighting)

source $ZSH/oh-my-zsh.sh
[[ -f ~/.p10k.zsh ]] && source ~/.p10k.zsh

# Aliases
alias ll='ls -lah'
alias gs='git status'
alias gp='git push'
alias v='nvim'
alias c='clear'
alias reload!='exec zsh'

# Terminal & history
export TERM=xterm-256color
HISTSIZE=10000
SAVEHIST=10000
HISTFILE=~/.zsh_history
EOF

# שלב 6: טען מחדש
echo "🔄 טוען מחדש את zsh..."
exec zsh
