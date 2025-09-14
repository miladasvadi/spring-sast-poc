# Models Review for Spring SAST Project

## CodeBERT
- Pros: trained on source code (Java included), good for embeddings, widely used in bug/vulnerability research.
- Cons: medium size (~125M params), not fine-tuned for Spring-specific vulns.

## GraphCodeBERT
- Pros: adds AST/dataflow info, stronger structural understanding.
- Cons: heavier and more complex to use.

## CodeT5
- Pros: strong for code-to-text, summarization, and defect detection tasks.
- Cons: less direct for vulnerability detection, harder fine-tuning.

## GPT (general LLMs)
- Pros: strong general reasoning, usable via API without fine-tuning.
- Cons: expensive, less reproducible, not specialized for static code analysis.

---

## Recommended Choice
**CodeBERT-base** is chosen as the initial model.  
Reason: balance of size, availability, Java coverage, and prior research use in vulnerability detection. Suitable for embeddings and FP reduction in our SAST PoC.
