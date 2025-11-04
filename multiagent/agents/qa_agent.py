import asyncio
import logging
from langchain.chains import RetrievalQA
from langchain_community.chat_models import AzureChatOpenAI
from langchain.prompts import PromptTemplate
from autogen_agentchat.messages import TextMessage

logger = logging.getLogger(__name__)

vectorstore = None
config = None


def set_vectorstore(vs):
    global vectorstore
    vectorstore = vs


def set_config(cfg):
    global config
    config = cfg


async def answer_question_from_db(question: str) -> TextMessage:
    """
    Full RAG implementation:
    1. Retrieve relevant chunks from MongoDB.
    2. Inject them into a prompt template.
    3. Generate an answer using AzureChatOpenAI.
    """

    if vectorstore is None or config is None:
        raise ValueError("Vectorstore or config not initialized. Please call set_vectorstore and set_config first.")

    try:
        # 🔹 Step 1: Create retriever
        retriever = vectorstore.as_retriever(search_kwargs={"k": 3})

        # 🔹 Step 2: Define custom prompt (forces direct, factual answers)
        rag_prompt = PromptTemplate(
            template=(
                "You are an intelligent assistant. "
                "Use the provided context to answer the question accurately and concisely. "
                "If the context does not contain the answer, say 'I couldn’t find that information.'\n\n"
                "Context:\n{context}\n\n"
                "Question: {question}\n"
                "Answer:"
            ),
            input_variables=["context", "question"],
        )

        # 🔹 Step 3: Initialize Azure LLM
        llm = AzureChatOpenAI(
            azure_endpoint=config[0]["base_url"],
            openai_api_version=config[0]["api_version"],
            deployment_name=config[0]["model"],
            openai_api_key=config[0]["openai_api_key"],
            temperature=0.3,
            max_tokens=400
        )

        # 🔹 Step 4: Build RetrievalQA chain with custom prompt
        qa_chain = RetrievalQA.from_chain_type(
            llm=llm,
            chain_type="stuff",
            retriever=retriever,
            return_source_documents=True,
            chain_type_kwargs={"prompt": rag_prompt}
        )

        # 🔹 Step 5: Run the chain properly
        result = await asyncio.to_thread(qa_chain.run, question)

        # 🔹 Step 6: Optional — retrieve sources for explainability
        docs = await asyncio.to_thread(retriever.get_relevant_documents, question)
        sources = [doc.metadata.get("filename", "unknown") for doc in docs]
        sources_text = ", ".join(set(sources)) if sources else "None"

        # 🔹 Step 7: Return final message
        final_answer = f"{result}\n\nSources: {sources_text}"
        return TextMessage(content=final_answer, source="RAG")

    except Exception as e:
        logger.error(f"LangChain-based RAG QA failed: {e}")
        return TextMessage(content=f"Error during RAG QA: {e}", source="RAG")
