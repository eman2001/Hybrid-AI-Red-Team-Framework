ollama pull llama3.1   # إذا لسا ما سحبتيه
ollama serve &          # إذا مش شغّال أصلاً كـ service

python3 -c "
from engine.modules.web_security.websec_engine import WebSecurityEngine
from engine.modules.web_security.ollama_summary import generate_executive_summary, is_ollama_available

print('Ollama available:', is_ollama_available())

eng = WebSecurityEngine('http://localhost:3000', timeout=10)
report = eng.run_all()

summary_text = generate_executive_summary(report)
print('--- Executive Summary ---')
print(summary_text)
"
